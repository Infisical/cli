package agentvault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

const (
	sessionInactiveTTL = 10 * time.Minute

	maxSessionCacheEntries = 4096

	// How long to keep serving when Infisical is unreachable - a timeout or a 5xx, as distinct from a 401.
	unreachableGraceIntervals = 5

	// The shared CLI client sets retries but no deadline, so a control plane that stalls would hang the poll loop.
	controlPlaneTimeout = 15 * time.Second
)

// Bytes are deliberately not zeroed on eviction: the copies handed to callers make it a false promise.
type credential struct {
	kind         string
	headerName   string
	headerPrefix string
	value        []byte
	username     string
	password     []byte
}

type resolvedConnection struct {
	id               string
	name             string
	accessBundleName string
	hostPatterns     []hostPattern
	credential       credential
}

type sessionEntry struct {
	sessionID   string
	expiresAt   *time.Time
	connections []*resolvedConnection
	lastSeen    time.Time
	fetchedAt   time.Time
}

// The map key is the sha256 of the token, never the token itself, so a heap dump yields no live credential.
func sessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type sessionResolver interface {
	resolve(sessionToken string) (*resolveResult, error)
}

type sessionCache struct {
	resolver     sessionResolver
	pollInterval func() time.Duration

	mu      sync.Mutex
	entries map[string]*sessionEntry
	tokens  map[string]string
}

func newSessionCache(resolver sessionResolver, pollInterval func() time.Duration) *sessionCache {
	return &sessionCache{
		resolver:     resolver,
		pollInterval: pollInterval,
		entries:      make(map[string]*sessionEntry),
		tokens:       make(map[string]string),
	}
}

var errSessionGone = errors.New("session is no longer valid")

// The name the server puts on a 401 that is about this proxy's own token rather than the session it asked
// about. Without it the two are the same status and the same error class.
const proxyTokenRejectedName = "ProxyTokenRejected"

func isProxyTokenRejected(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.Name == proxyTokenRejectedName
}

// A definitive refusal ends the session; only a status that can clear on its own rides the grace window.
// A 403 or 422 today can only mean the server changed its mind about the request, never a blip, so it is
// terminal too, as the sibling's isAuthError treats 403. A rejected proxy token is not a verdict on the
// session, so it is reported separately, though the caller drops the entry just the same.
func isSessionGone(err error) bool {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		if isProxyTokenRejected(err) {
			return false
		}
		s := apiErr.StatusCode
		return s >= 400 && s < 500 && s != http.StatusRequestTimeout && s != http.StatusTooManyRequests
	}
	return errors.Is(err, errSessionGone)
}

func (c *sessionCache) get(sessionToken string) ([]*resolvedConnection, error) {
	key := sessionKey(sessionToken)

	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok {
		if entry.expiresAt != nil && time.Now().After(*entry.expiresAt) {
			delete(c.entries, key)
			delete(c.tokens, key)
			c.mu.Unlock()
			return nil, errSessionGone
		}
		// Past the grace window the entry is a miss, so a stalled refresh loop cannot keep an old credential alive.
		if time.Since(entry.fetchedAt) > c.grace() {
			delete(c.entries, key)
			delete(c.tokens, key)
		} else {
			entry.lastSeen = time.Now()
			conns := entry.connections
			c.mu.Unlock()
			return conns, nil
		}
	}
	c.mu.Unlock()

	result, err := c.resolver.resolve(sessionToken)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfFullLocked()
	c.entries[key] = &sessionEntry{
		sessionID:   result.SessionID,
		expiresAt:   result.ExpiresAt,
		connections: result.Connections,
		lastSeen:    time.Now(),
		fetchedAt:   time.Now(),
	}
	c.tokens[key] = sessionToken
	return result.Connections, nil
}

func (c *sessionCache) evictIfFullLocked() {
	if len(c.entries) < maxSessionCacheEntries {
		return
	}

	now := time.Now()
	var victim string
	var oldest time.Time
	for key, entry := range c.entries {
		if now.Sub(entry.lastSeen) > sessionInactiveTTL {
			victim = key
			break
		}
		if victim == "" || entry.lastSeen.Before(oldest) {
			victim, oldest = key, entry.lastSeen
		}
	}
	if victim == "" {
		return
	}
	delete(c.entries, victim)
	delete(c.tokens, victim)
}

func (c *sessionCache) refresh() {
	c.mu.Lock()
	targets := make(map[string]string, len(c.tokens))
	now := time.Now()
	for key, entry := range c.entries {
		if now.Sub(entry.lastSeen) > sessionInactiveTTL {
			delete(c.entries, key)
			delete(c.tokens, key)
			continue
		}
		if entry.expiresAt != nil && now.After(*entry.expiresAt) {
			delete(c.entries, key)
			delete(c.tokens, key)
			continue
		}
		targets[key] = c.tokens[key]
	}
	c.mu.Unlock()

	for key, token := range targets {
		result, err := c.resolver.resolve(token)
		if err != nil {
			c.handleRefreshFailure(key, err)
			continue
		}

		c.mu.Lock()
		if entry, ok := c.entries[key]; ok {
			entry.sessionID = result.SessionID
			entry.expiresAt = result.ExpiresAt
			entry.connections = result.Connections
			entry.fetchedAt = time.Now()
		}
		c.mu.Unlock()
	}
}

func (c *sessionCache) handleRefreshFailure(key string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return
	}

	// Both drop the entry at once: a rejected proxy token is the operator's kill switch, so nothing cached
	// may outlive it. Only the reason logged differs.
	if isProxyTokenRejected(err) {
		log.Warn().Err(err).Str("sessionId", entry.sessionID).Msg("agent-vault: Infisical rejected this proxy's token, dropping the session")
		delete(c.entries, key)
		delete(c.tokens, key)
		return
	}
	if isSessionGone(err) {
		log.Debug().Err(err).Str("sessionId", entry.sessionID).Msg("agent-vault: session no longer valid, dropping")
		delete(c.entries, key)
		delete(c.tokens, key)
		return
	}

	grace := c.grace()
	if time.Since(entry.fetchedAt) > grace {
		log.Warn().
			Str("sessionId", entry.sessionID).
			Dur("grace", grace).
			Msg("agent-vault: could not reach Infisical within the grace window, dropping session")
		delete(c.entries, key)
		delete(c.tokens, key)
	}
}

func (c *sessionCache) grace() time.Duration {
	return time.Duration(unreachableGraceIntervals) * c.pollInterval()
}

func (c *sessionCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		delete(c.entries, key)
		delete(c.tokens, key)
	}
}
