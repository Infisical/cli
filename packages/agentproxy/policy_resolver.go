package agentproxy

import (
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	// A session is dropped from the cache after this long without a request, so an agent that has finished
	// stops costing a refresh and its credential values leave memory.
	sessionInactiveTTL = 10 * time.Minute

	// The cache key is a session token minted by Infisical, so entries cannot be forged, but a busy bot can
	// still hold thousands. Bounded so memory stays predictable; the least-recently-seen session is evicted.
	maxSessionCacheEntries = 4096

	// Activity is batched rather than sent per request: one audit call per flush, and a request never waits
	// on the audit write.
	maxPendingActivityEvents = 500
)

type sessionEntry struct {
	token         string
	agentName     string
	agentPolicies []*resolvedAgentPolicy
	userPolicies  []*resolvedUserPolicy
	allowedHosts  []string
	lastSeen      time.Time
}

// policyResolver holds the proxy's view of every live session. Everything in it comes from Infisical and
// is re-fetched on a poll, so revocation needs no cache invalidation here: the refresh either returns new
// policies or fails closed and the session is dropped.
type policyResolver struct {
	proxyToken func() string

	mu       sync.Mutex
	sessions map[string]*sessionEntry

	activityMu sync.Mutex
	activity   map[string][]api.AgentSessionActivityEvent
	dropped    int
}

func newPolicyResolver(proxyToken func() string) *policyResolver {
	return &policyResolver{
		proxyToken: proxyToken,
		sessions:   make(map[string]*sessionEntry),
		activity:   make(map[string][]api.AgentSessionActivityEvent),
	}
}

func (r *policyResolver) client() *resty.Client {
	return resty.New().SetAuthToken(r.proxyToken())
}

// get returns the cached session for a token, resolving it on first use. A failure is returned rather
// than cached, so a bad token never becomes a cached allow.
func (r *policyResolver) get(token string) (*sessionEntry, error) {
	r.mu.Lock()
	if entry := r.sessions[token]; entry != nil {
		entry.lastSeen = time.Now()
		r.mu.Unlock()
		return entry, nil
	}
	r.mu.Unlock()

	resolved, err := api.CallResolveAgentSession(r.client(), token)
	if err != nil {
		return nil, err
	}

	entry := buildSessionEntry(token, resolved)

	r.mu.Lock()
	r.evictIfFullLocked(token)
	r.sessions[token] = entry
	r.mu.Unlock()
	return entry, nil
}

func buildSessionEntry(token string, resolved api.ResolveAgentSessionResponse) *sessionEntry {
	entry := &sessionEntry{
		token:        token,
		agentName:    resolved.Session.AgentName,
		allowedHosts: resolved.AllowedHosts,
		lastSeen:     time.Now(),
	}

	for _, policy := range resolved.AgentPolicies {
		agentPolicy := &resolvedAgentPolicy{id: policy.ID, name: policy.Name}
		for _, rule := range policy.Rules {
			agentPolicy.rules = append(agentPolicy.rules, policyRule{pattern: parsePolicyPattern(rule.HostPattern, rule.Methods)})
		}
		for _, credential := range policy.Credentials {
			agentPolicy.credentials = append(agentPolicy.credentials, resolvedCredential{
				role:          credential.Role,
				headerName:    credential.HeaderName,
				headerPrefix:  credential.HeaderPrefix,
				headerPurpose: credential.HeaderPurpose,
				placeholder:   credential.PlaceholderValue,
				surfaces:      credential.SubstitutionSurfaces,
				value:         credential.Value,
			})
		}
		entry.agentPolicies = append(entry.agentPolicies, agentPolicy)
	}

	for _, policy := range resolved.UserPolicies {
		userPolicy := &resolvedUserPolicy{id: policy.ID, name: policy.Name}
		for _, rule := range policy.Rules {
			userPolicy.rules = append(userPolicy.rules, policyRule{pattern: parsePolicyPattern(rule.HostPattern, rule.Methods)})
		}
		entry.userPolicies = append(entry.userPolicies, userPolicy)
	}

	return entry
}

func (r *policyResolver) evictIfFullLocked(incoming string) {
	if len(r.sessions) < maxSessionCacheEntries {
		return
	}
	if _, replacing := r.sessions[incoming]; replacing {
		return
	}
	now := time.Now()
	for token, entry := range r.sessions {
		if now.Sub(entry.lastSeen) > sessionInactiveTTL {
			delete(r.sessions, token)
		}
	}
	for len(r.sessions) >= maxSessionCacheEntries {
		var oldestToken string
		var oldest time.Time
		for token, entry := range r.sessions {
			if oldestToken == "" || entry.lastSeen.Before(oldest) {
				oldestToken, oldest = token, entry.lastSeen
			}
		}
		delete(r.sessions, oldestToken)
	}
}

// refreshActive re-resolves every session that has been used recently. A hard auth failure means the
// session was revoked, the agent lost its flag, or the user left the project: drop it and fail closed.
func (r *policyResolver) refreshActive() {
	r.mu.Lock()
	tokens := make([]string, 0, len(r.sessions))
	for token, entry := range r.sessions {
		if time.Since(entry.lastSeen) > sessionInactiveTTL {
			delete(r.sessions, token)
			continue
		}
		tokens = append(tokens, token)
	}
	r.mu.Unlock()

	for _, token := range tokens {
		resolved, err := api.CallResolveAgentSession(r.client(), token)
		if err != nil {
			if isAuthError(err) {
				log.Warn().Err(err).Msg("session is no longer valid; dropping its cached policies and credentials")
				r.mu.Lock()
				delete(r.sessions, token)
				r.mu.Unlock()
				continue
			}
			log.Warn().Err(err).Msg("failed to refresh a session's policies; keeping the current ones")
			continue
		}

		fresh := buildSessionEntry(token, resolved)
		r.mu.Lock()
		if existing, ok := r.sessions[token]; ok {
			fresh.lastSeen = existing.lastSeen
			r.sessions[token] = fresh
		}
		r.mu.Unlock()
	}
}

func (r *policyResolver) close() {
	r.mu.Lock()
	r.sessions = make(map[string]*sessionEntry)
	r.mu.Unlock()
}

// recordActivity queues one audit event. It never blocks the request: when the queue is full the event is
// counted and dropped, and the count is logged at flush so a silent gap in the trail is visible.
func (r *policyResolver) recordActivity(token string, event api.AgentSessionActivityEvent) {
	r.activityMu.Lock()
	defer r.activityMu.Unlock()

	total := 0
	for _, events := range r.activity {
		total += len(events)
	}
	if total >= maxPendingActivityEvents {
		r.dropped++
		return
	}
	r.activity[token] = append(r.activity[token], event)
}

func (r *policyResolver) flushActivity() {
	r.activityMu.Lock()
	pending := r.activity
	dropped := r.dropped
	r.activity = make(map[string][]api.AgentSessionActivityEvent)
	r.dropped = 0
	r.activityMu.Unlock()

	if dropped > 0 {
		log.Warn().Msgf("dropped %d activity event(s) because the audit queue was full", dropped)
	}

	for token, events := range pending {
		if len(events) == 0 {
			continue
		}
		if err := api.CallRecordAgentSessionActivity(r.client(), token, events); err != nil {
			log.Warn().Err(err).Msgf("failed to record %d activity event(s)", len(events))
		}
	}
}
