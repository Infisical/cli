package agentproxy

import (
	"errors"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// How long a resolved bundle may be served before it is re-fetched. This is what bounds how long a rotated
// secret, a revoked grant, or a disabled service can keep being applied.
const defaultBundleTTL = 60 * time.Second

// ErrSessionRevoked means the session is no longer usable and the caller should tear down rather than keep
// serving. Returned on 401/403/404 so revocation fails closed and loudly, instead of the agent silently
// continuing with unbrokered requests.
var ErrSessionRevoked = errors.New("agent gateway session is no longer valid")

type bundleEntry struct {
	services  []*resolvedService
	etag      string
	fetchedAt time.Time
	lastSeen  time.Time
}

// bundleResolver serves both the gateway (many sessions, one process) and local mode (exactly one). The
// only difference is which token it presents, which is why there is no separate local resolver any more.
type bundleResolver struct {
	token func() string
	ttl   time.Duration

	mu      sync.Mutex
	entries map[string]*bundleEntry
	revoked map[string]struct{}
}

func newBundleResolver(token func() string, ttl time.Duration) *bundleResolver {
	if ttl <= 0 {
		ttl = defaultBundleTTL
	}
	return &bundleResolver{
		token:   token,
		ttl:     ttl,
		entries: make(map[string]*bundleEntry),
		revoked: make(map[string]struct{}),
	}
}

// Keyed by session id alone. Not by (project, environment, path) as the old cache was, and not by token:
// a session is the thing credentials belong to, and its identity came from a certificate the backend signed.
func (r *bundleResolver) services(session Session) ([]*resolvedService, error) {
	if session.expired() {
		return nil, ErrSessionRevoked
	}

	r.mu.Lock()
	if _, gone := r.revoked[session.ID]; gone {
		r.mu.Unlock()
		return nil, ErrSessionRevoked
	}
	entry := r.entries[session.ID]
	if entry != nil {
		entry.lastSeen = time.Now()
		if time.Since(entry.fetchedAt) < r.ttl {
			services := entry.services
			r.mu.Unlock()
			return services, nil
		}
	}
	r.mu.Unlock()

	return r.fetch(session)
}

func (r *bundleResolver) fetch(session Session) ([]*resolvedService, error) {
	r.mu.Lock()
	existing := r.entries[session.ID]
	var etag string
	if existing != nil {
		etag = existing.etag
	}
	r.mu.Unlock()

	client := resty.New().SetAuthToken(r.token())
	bundle, nextETag, notModified, err := api.CallGetAgentGatewayBrokerBundle(client, session.ID, etag)
	if err != nil {
		if isAuthError(err) {
			// Fail closed: drop what we hold so nothing keeps being applied after the grant went away.
			r.forget(session.ID, true)
			return nil, ErrSessionRevoked
		}
		// A transient backend problem keeps the previous snapshot rather than breaking a running agent. The
		// session's own expiry is the backstop.
		if existing != nil {
			log.Warn().Err(err).Msgf("agent gateway: bundle refresh failed, serving the previous one [sessionId=%s]", session.ID)
			return existing.services, nil
		}
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if notModified && existing != nil {
		existing.fetchedAt = time.Now()
		existing.lastSeen = time.Now()
		return existing.services, nil
	}

	services := bundleToServices(bundle)
	r.entries[session.ID] = &bundleEntry{
		services:  services,
		etag:      nextETag,
		fetchedAt: time.Now(),
		lastSeen:  time.Now(),
	}
	return services, nil
}

// Called when a session's transport closes. Dropping immediately rather than waiting for an idle sweep is
// what keeps a finished agent's credentials from lingering in memory.
func (r *bundleResolver) forget(sessionID string, markRevoked bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, sessionID)
	if markRevoked {
		r.revoked[sessionID] = struct{}{}
	}
}

// Drops anything untouched for longer than the idle window, so a gateway serving many short agent runs does
// not accumulate their credentials.
func (r *bundleResolver) evictIdle(idleFor time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, entry := range r.entries {
		if time.Since(entry.lastSeen) > idleFor {
			delete(r.entries, id)
		}
	}
}

func (r *bundleResolver) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = make(map[string]*bundleEntry)
}
