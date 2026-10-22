package agentvault

import (
	"sync/atomic"

	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sync/singleflight"
	"net/http"
	"slices"
	"strings"
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

	refreshParallelism = 8

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
	// Only an OAuth token Infisical issued can be refreshed when the upstream rejects it.
	refreshable bool
}

type customHeader struct {
	name   string
	prefix string
	value  []byte
}

type substitution struct {
	placeholder string
	surfaces    map[string]bool
	value       []byte
}

type resolvedService struct {
	id               string
	name             string
	kind             string
	accessBundleName string
	// As Infisical sent it, so a credential refresh can name the destination the rejected token went to.
	hostPattern  string
	hostPatterns []hostPattern
	// A nil map means every method is allowed; an empty slice of prefixes means every path.
	allowedMethods      map[string]bool
	allowedPathPrefixes []string
	credential          credential
	customHeaders       []customHeader
	substitutions       []substitution
}

type sessionEntry struct {
	sessionID  string
	expiresAt  *time.Time
	services   []*resolvedService
	sessionLog *sessionLogGrant
	lastSeen   time.Time
	fetchedAt  time.Time
	// Keyed by service ID. A poll whose resolve began before a swap can return the token that swap replaced,
	// so the merge consults this to keep the newer one.
	swaps map[string]*credentialSwap
}

type credentialSwap struct {
	installed   credential
	hostPattern string
	replaced    map[string]bool
	gen         uint64
}

// The map key is the sha256 of the token, never the token itself, so a heap dump yields no live credential.
func sessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type sessionResolver interface {
	resolve(sessionToken string, held *sessionLogGrant) (*resolveResult, error)
}

// Implemented by the Infisical resolver. Kept apart from sessionResolver so resolvers that never broker an
// OAuth credential need not stub it.
type credentialRefresher interface {
	refreshCredential(sessionToken, serviceID, hostPattern, rejectedHash string) (credential, string, error)
	reportMissingScopes(sessionToken, serviceID, hostPattern, rejectedHash string, requiredScopes []string) error
}

type sessionCache struct {
	resolver     sessionResolver
	pollInterval func() time.Duration

	// Concurrent misses for one session share a single resolve rather than each posting to Infisical.
	inflight singleflight.Group
	// Concurrent upstream 401s for one service share a single refresh, so a burst of requests holding the
	// same expired token costs Infisical one call.
	credentialFlights singleflight.Group
	// A refresh that outlives the poll interval must not pile a second one on top, nor hold up the heartbeat.
	refreshing atomic.Bool

	mu      sync.Mutex
	entries map[string]*sessionEntry
	tokens  map[string]string
	// A definitive refusal is remembered briefly, so an agent retrying a dead session costs one resolve per
	// window rather than one per request. Outages and throttling are never stored here.
	refused map[string]refusedEntry
	// A failed credential refresh is remembered the same way, per service and rejected token, so while
	// Infisical is down or slow each request carrying that token gets its 502 at once rather than another
	// refresh that can take the whole control-plane timeout.
	failedRefreshes map[string]refusedEntry
	// Bumped under mu by every credential swap, so a poll can tell which swaps happened after it began.
	swapGen uint64
}

type refusedEntry struct {
	err   error
	until time.Time
}

const (
	refusedTTL        = 5 * time.Second
	maxRefusedEntries = 4096
)

func newSessionCache(resolver sessionResolver, pollInterval func() time.Duration) *sessionCache {
	return &sessionCache{
		resolver:        resolver,
		pollInterval:    pollInterval,
		entries:         make(map[string]*sessionEntry),
		tokens:          make(map[string]string),
		refused:         make(map[string]refusedEntry),
		failedRefreshes: make(map[string]refusedEntry),
	}
}

func (c *sessionCache) rememberRefusalLocked(key string, err error) {
	c.refused = rememberLocked(c.refused, key, err)
}

func rememberLocked(entries map[string]refusedEntry, key string, err error) map[string]refusedEntry {
	if len(entries) >= maxRefusedEntries {
		entries = make(map[string]refusedEntry)
	}
	entries[key] = refusedEntry{err: err, until: time.Now().Add(refusedTTL)}
	return entries
}

var errSessionGone = errors.New("session is no longer valid")

// The name the server puts on a 401 that is about this proxy's own token rather than the session it asked
// about. Without it the two are the same status and the same error class.
const proxyTokenRejectedName = "ProxyTokenRejected"

func isProxyTokenRejected(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.Name == proxyTokenRejectedName
}

// The names on Infisical's own 404s and 401s. A route miss, a middlebox or an auth proxy in front of Infisical
// answers under another name or none.
const (
	infisicalNotFoundName     = "NotFound"
	infisicalUnauthorizedName = "UnauthorizedError"
)

// Resolve answers 200, 401 or 404 by contract, and 401 with a name when the proxy's own token is the
// problem. Only Infisical's own 401 (UnauthorizedError) or 404 (NotFound) is a verdict on the session; any
// other 4xx, an unnamed one included, is a proxy-side fault or a middlebox, and the heartbeat classifier reads a
// 4xx the same way, so the two agree. A rejected proxy token is not a verdict on the session and is reported
// separately.
func isSessionGone(err error) bool {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		if isProxyTokenRejected(err) {
			return false
		}
		return (apiErr.StatusCode == http.StatusUnauthorized && apiErr.Name == infisicalUnauthorizedName) ||
			(apiErr.StatusCode == http.StatusNotFound && apiErr.Name == infisicalNotFoundName)
	}
	return errors.Is(err, errSessionGone)
}

func (c *sessionCache) get(sessionToken string) ([]*resolvedService, error) {
	services, _, err := c.lookup(sessionToken)
	return services, err
}

type cacheLookup struct {
	services   []*resolvedService
	sessionLog *sessionLogGrant
}

func (c *sessionCache) lookup(sessionToken string) ([]*resolvedService, *sessionLogGrant, error) {
	key := sessionKey(sessionToken)

	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok {
		if entry.expiresAt != nil && time.Now().After(*entry.expiresAt) {
			delete(c.entries, key)
			delete(c.tokens, key)
			c.mu.Unlock()
			return nil, nil, errSessionGone
		}
		// Past the grace window the entry is a miss, so a stalled refresh loop cannot keep an old credential alive.
		if time.Since(entry.fetchedAt) > c.grace() {
			delete(c.entries, key)
			delete(c.tokens, key)
		} else {
			entry.lastSeen = time.Now()
			svcs, grant := entry.services, entry.sessionLog
			c.mu.Unlock()
			return svcs, grant, nil
		}
	}
	if refused, ok := c.refused[key]; ok {
		if time.Now().Before(refused.until) {
			c.mu.Unlock()
			return nil, nil, refused.err
		}
		delete(c.refused, key)
	}
	c.mu.Unlock()

	resolved, err, _ := c.inflight.Do(key, func() (any, error) {
		result, err := c.resolver.resolve(sessionToken, nil)
		if err != nil {
			// A rejected proxy token is remembered too: the poll loop exits after two such heartbeats, but
			// until then every agent request would otherwise cost a resolve.
			if isSessionGone(err) || isProxyTokenRejected(err) {
				c.mu.Lock()
				c.rememberRefusalLocked(key, err)
				c.mu.Unlock()
			}
			return nil, err
		}

		c.mu.Lock()
		defer c.mu.Unlock()
		c.evictIfFullLocked()
		c.entries[key] = &sessionEntry{
			sessionID:  result.SessionID,
			expiresAt:  result.ExpiresAt,
			services:   result.Services,
			sessionLog: result.SessionLog,
			lastSeen:   time.Now(),
			fetchedAt:  time.Now(),
		}
		c.tokens[key] = sessionToken
		return cacheLookup{services: result.Services, sessionLog: result.SessionLog}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	out := resolved.(cacheLookup)
	return out.services, out.sessionLog, nil
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

// refreshInBackground runs one refresh at a time off the caller's goroutine, so a slow control plane
// delays neither the heartbeat nor the next tick. A tick that finds one still running skips it.
func (c *sessionCache) refreshInBackground() {
	if !c.refreshing.CompareAndSwap(false, true) {
		log.Warn().Msg("agent-vault: the previous session refresh is still running, skipping this one")
		return
	}
	go func() {
		defer c.refreshing.Store(false)
		c.refresh()
	}()
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

	// Bounded rather than one at a time: twenty sessions against a slow control plane took minutes in
	// series, long enough for later entries to age past the grace window before their turn came.
	slots := make(chan struct{}, refreshParallelism)
	var wg sync.WaitGroup
	for key, token := range targets {
		wg.Add(1)
		slots <- struct{}{}
		go func(key, token string) {
			defer wg.Done()
			defer func() { <-slots }()
			c.refreshOne(key, token)
		}(key, token)
	}
	wg.Wait()
}

func (c *sessionCache) refreshOne(key, token string) {
	c.mu.Lock()
	var held *sessionLogGrant
	if entry, ok := c.entries[key]; ok {
		held = entry.sessionLog
	}
	startGen := c.swapGen
	c.mu.Unlock()

	result, err := c.resolver.resolve(token, held)
	if err != nil {
		c.handleRefreshFailure(key, err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		entry.sessionID = result.SessionID
		entry.expiresAt = result.ExpiresAt
		entry.services = keepNewerSwaps(entry, result.Services, startGen)
		entry.sessionLog = result.SessionLog
		entry.fetchedAt = time.Now()
	}
}

// keepNewerSwaps puts back a credential swapped in after the poll began when the poll returned a token that
// swap replaced. Swaps the poll began after are settled by it and forgotten.
func keepNewerSwaps(entry *sessionEntry, polled []*resolvedService, startGen uint64) []*resolvedService {
	if len(entry.swaps) == 0 {
		return polled
	}
	services, copied := polled, false
	for i, svc := range polled {
		swap, ok := entry.swaps[svc.id]
		if !ok || swap.gen <= startGen || swap.hostPattern != svc.hostPattern || !svc.credential.refreshable || !swap.replaced[credentialHash(&svc.credential)] {
			continue
		}
		if !copied {
			services, copied = append([]*resolvedService(nil), polled...), true
		}
		updated := *svc
		updated.credential = swap.installed
		services[i] = &updated
	}
	for id, swap := range entry.swaps {
		if swap.gen <= startGen {
			delete(entry.swaps, id)
		}
	}
	return services
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

var (
	errCredentialNotRefreshable = errors.New("the refresh did not return a refreshable credential")
	errServiceHostChanged       = errors.New("the service's host pattern changed while its credential was refreshed")
	errServiceRemoved           = errors.New("the service was removed from the session while its credential was refreshed")
)

func credentialHash(cred *credential) string {
	sum := sha256.Sum256(cred.value)
	return hex.EncodeToString(sum[:])
}

// refreshCredential asks Infisical for a replacement of the token the upstream rejected and swaps it into
// the session's entry, so later requests inject it. hostPattern is that of the cached service whose
// credential the rejected request carried: a token minted for wherever the service points now must never be
// sent to where it used to point. The status is Infisical's view of the service's OAuth connection, empty
// when the answer did not come from Infisical.
func (c *sessionCache) refreshCredential(sessionToken, serviceID, hostPattern string, rejected *credential) (credential, string, error) {
	refresher, ok := c.resolver.(credentialRefresher)
	if !ok {
		return credential{}, "", errCredentialNotRefreshable
	}
	key := sessionKey(sessionToken)
	rejectedHash := credentialHash(rejected)

	type refreshed struct {
		cred   credential
		status string
	}
	flightKey := credentialFlightKey(key, serviceID, hostPattern, rejectedHash, nil)
	result, err, _ := c.credentialFlights.Do(flightKey, func() (any, error) {
		// Checked inside the flight so a caller that arrives after another refresh finished also reuses
		// its replacement instead of asking Infisical again.
		if current, ok := c.currentCredential(key, serviceID, hostPattern); ok && current.refreshable && credentialHash(&current) != rejectedHash {
			return refreshed{cred: current}, nil
		}
		if err := c.recentRefreshFailure(flightKey); err != nil {
			return nil, err
		}
		fresh, status, err := refresher.refreshCredential(sessionToken, serviceID, hostPattern, rejectedHash)
		if err != nil {
			c.rememberRefreshFailure(flightKey, err)
			return nil, err
		}
		if status != "" && status != oauthStatusConnected {
			log.Warn().Str("serviceId", serviceID).Str("status", status).
				Msg("agent-vault: Infisical reports this service's OAuth connection needs attention")
		}
		if fresh.kind != credentialBearer || !fresh.refreshable {
			c.rememberRefreshFailure(flightKey, errCredentialNotRefreshable)
			return nil, errCredentialNotRefreshable
		}
		swapped, err := c.swapCredential(key, serviceID, hostPattern, rejectedHash, fresh)
		if err != nil {
			return nil, err
		}
		return refreshed{cred: swapped, status: status}, nil
	})
	if err != nil {
		return credential{}, "", err
	}
	answer := result.(refreshed)
	return answer.cred, answer.status, nil
}

func (c *sessionCache) recentRefreshFailure(flightKey string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	failed, ok := c.failedRefreshes[flightKey]
	if !ok {
		return nil
	}
	if time.Now().Before(failed.until) {
		return failed.err
	}
	delete(c.failedRefreshes, flightKey)
	return nil
}

func (c *sessionCache) rememberRefreshFailure(flightKey string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failedRefreshes = rememberLocked(c.failedRefreshes, flightKey, err)
}

// reportMissingScopes tells Infisical which scopes the upstream's 403 insufficient_scope challenge asked for,
// so the service shows what reauthorizing has to request. Nothing is refreshed, so the cache is left alone.
func (c *sessionCache) reportMissingScopes(sessionToken, serviceID, hostPattern string, rejected *credential, requiredScopes []string) error {
	refresher, ok := c.resolver.(credentialRefresher)
	if !ok {
		return errCredentialNotRefreshable
	}
	rejectedHash := credentialHash(rejected)
	_, err, _ := c.credentialFlights.Do(credentialFlightKey(sessionKey(sessionToken), serviceID, hostPattern, rejectedHash, requiredScopes), func() (any, error) {
		return nil, refresher.reportMissingScopes(sessionToken, serviceID, hostPattern, rejectedHash, requiredScopes)
	})
	return err
}

// Scope reports are bound to the rejected token, so neither different tokens nor different scope sets may
// share a call. The set is canonical so another order or repeats still share one call.
func credentialFlightKey(key, serviceID, hostPattern, rejectedHash string, requiredScopes []string) string {
	base := key + "\x00" + serviceID + "\x00" + hostPattern + "\x00" + rejectedHash
	if len(requiredScopes) == 0 {
		return base + "\x00refresh"
	}
	scopes := append([]string(nil), requiredScopes...)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	return base + "\x00scopes\x00" + strings.Join(scopes, " ")
}

func (c *sessionCache) currentCredential(key, serviceID, hostPattern string) (credential, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return credential{}, false
	}
	for _, svc := range entry.services {
		if svc.id == serviceID && svc.hostPattern == hostPattern {
			return svc.credential, true
		}
	}
	return credential{}, false
}

// Copy on write: requests in flight hold pointers into the old slice and read it without the lock. A newer
// cached credential wins over a delayed refresh or scope report, including the credential returned for retry.
// A poll that removed the session or the service during the refresh revoked that access, so the fresh token
// is refused rather than handed to a retry.
func (c *sessionCache) swapCredential(key, serviceID, hostPattern, replacedHash string, cred credential) (credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return credential{}, errSessionGone
	}
	for i, svc := range entry.services {
		if svc.id != serviceID {
			continue
		}
		if svc.hostPattern != hostPattern {
			return credential{}, errServiceHostChanged
		}
		if !svc.credential.refreshable {
			return credential{}, errCredentialNotRefreshable
		}
		if credentialHash(&svc.credential) != replacedHash {
			return svc.credential, nil
		}
		updated := *svc
		updated.credential = cred
		services := append([]*resolvedService(nil), entry.services...)
		services[i] = &updated
		entry.services = services

		c.swapGen++
		if entry.swaps == nil {
			entry.swaps = make(map[string]*credentialSwap)
		}
		swap, ok := entry.swaps[serviceID]
		if !ok {
			swap = &credentialSwap{replaced: make(map[string]bool)}
			entry.swaps[serviceID] = swap
		}
		swap.installed = cred
		if swap.hostPattern != hostPattern {
			swap.hostPattern = hostPattern
			clear(swap.replaced)
		}
		swap.replaced[replacedHash] = true
		swap.gen = c.swapGen
		// A scope report swaps in the token it reported, which is current rather than stale.
		delete(swap.replaced, credentialHash(&cred))
		return cred, nil
	}
	return credential{}, errServiceRemoved
}
