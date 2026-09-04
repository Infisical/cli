package agentvault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

const (
	// A session nobody has used for this long stops being polled and is dropped.
	sessionInactiveTTL = 10 * time.Minute

	// Bounds the cache so a proxy serving many agents cannot grow it until it runs out of memory. When
	// full, idle entries go first, then the least-recently-seen.
	maxSessionCacheEntries = 4096

	// How long to keep serving when Infisical is unreachable — a timeout or a 5xx, as distinct from a
	// 401. One interval would kill every running agent on a blip; the shipped proxied-service cache
	// serves indefinitely, which is the worse bug.
	unreachableGraceIntervals = 5
)

// credential is the decrypted half.
//
// Bytes are deliberately not zeroed on eviction or refresh. Zeroing only defends against someone who can
// read this process's memory, and anyone in that position is on the proxy's own box, where the proxy
// token sits on disk and can resolve every live session's credentials directly. Zeroing in place also
// raced with in-flight requests that still held the slice, so a refresh could send \x00 bytes upstream.
type credential struct {
	kind         string
	headerName   string
	headerPrefix string
	value        []byte
	username     string
	password     []byte
}

type resolvedConnection struct {
	id string
	// Carried so the decision log can say which access bundle a host came from. Resolve is the only place
	// that knows it.
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

// sessionKey is the sha256 of the token, never the token. In the shipped proxied-service cache the raw
// JWT is both the map key and a field on the entry, so a heap dump yields every live credential verbatim.
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
	// Tokens are held only so the refresh loop can re-resolve; keyed by hash like everything else.
	tokens map[string]string
}

func newSessionCache(resolver sessionResolver, pollInterval func() time.Duration) *sessionCache {
	return &sessionCache{
		resolver:     resolver,
		pollInterval: pollInterval,
		entries:      make(map[string]*sessionEntry),
		tokens:       make(map[string]string),
	}
}

// errSessionGone means drop the entry now: revoked, expired, or the session row is gone.
var errSessionGone = errors.New("session is no longer valid")

func isSessionGone(err error) bool {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		// 401 is revoked or expired. 404 is the session row gone (the actor was deleted) or a proxy/org
		// mismatch. A 404 is neither a 401 nor a 5xx, so without its own arm it would fall into the
		// unreachable-Infisical branch below and keep brokering for five more intervals — precisely the
		// case where the proxy should stop soonest.
		return apiErr.StatusCode == 401 || apiErr.StatusCode == 404
	}
	return errors.Is(err, errSessionGone)
}

func (c *sessionCache) get(sessionToken string) ([]*resolvedConnection, error) {
	key := sessionKey(sessionToken)

	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok {
		if entry.expiresAt != nil && time.Now().After(*entry.expiresAt) {
			// Expired locally: no call needed, and none would succeed.
			delete(c.entries, key)
			delete(c.tokens, key)
			c.mu.Unlock()
			return nil, errSessionGone
		}
		entry.lastSeen = time.Now()
		conns := entry.connections
		c.mu.Unlock()
		return conns, nil
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

// evictIfFullLocked drops an idle entry first, and only then the least-recently-seen one, so an actively
// used session keeps its cache while idle ones go.
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

// refresh re-resolves every live session. Called once per poll tick, so the worst-case staleness of any
// change an administrator makes is one interval, and there is no second place to invalidate.
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
			c.handleRefreshFailureLocked(key, err)
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

func (c *sessionCache) handleRefreshFailureLocked(key string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return
	}

	if isSessionGone(err) {
		log.Debug().Str("sessionId", entry.sessionID).Msg("agent-vault: session no longer valid, dropping")
		delete(c.entries, key)
		delete(c.tokens, key)
		return
	}

	// Unreachable Infisical. Keep serving for a bounded window, then fail closed.
	grace := time.Duration(unreachableGraceIntervals) * c.pollInterval()
	if time.Since(entry.fetchedAt) > grace {
		log.Warn().
			Str("sessionId", entry.sessionID).
			Dur("grace", grace).
			Msg("agent-vault: could not reach Infisical within the grace window, dropping session")
		delete(c.entries, key)
		delete(c.tokens, key)
	}
}

func (c *sessionCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		delete(c.entries, key)
		delete(c.tokens, key)
	}
}
