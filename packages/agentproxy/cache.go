package agentproxy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

func isAuthError(err error) bool {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 401 || apiErr.StatusCode == 403
	}
	return false
}

const agentInactiveTTL = 10 * time.Minute

// maxAgentCacheEntries bounds the resolution cache. Its key includes the client-supplied scope
// (project/env/path), so without a cap an authenticated agent could vary the scope indefinitely and
// grow the map until the proxy runs out of memory. When full, the least-recently-seen entry is evicted,
// so actively-used agents keep their cache and only idle scopes are dropped.
const maxAgentCacheEntries = 4096

// dynamicCredentialRef points a credential at a lease in the lease store. The value is resolved per-request
// (materialized) rather than stored here, so poll re-resolves and agent eviction never touch live leases.
type dynamicCredentialRef struct {
	key   leaseKey
	field string
}

type resolvedCredential struct {
	role          string
	headerName    string
	headerPrefix  string
	headerPurpose string
	placeholder   string
	surfaces      []string
	value         string
	dynamic       *dynamicCredentialRef
}

type resolvedService struct {
	name         string
	hostPatterns []hostPattern
	isEnabled    bool
	credentials  []resolvedCredential
}

type agentScope struct {
	projectID   string
	environment string
	secretPath  string
}

type agentEntry struct {
	jwt      string
	scope    agentScope
	services []*resolvedService
	lastSeen time.Time
}

func cacheKey(jwt string, scope agentScope) string {
	return strings.Join([]string{jwt, scope.projectID, scope.environment, scope.secretPath}, "\x00")
}

type agentCache struct {
	proxyToken func() string
	leases     *leaseStore

	mu      sync.Mutex
	entries map[string]*agentEntry
}

func newAgentCache(proxyToken func() string, leases *leaseStore) *agentCache {
	return &agentCache{
		proxyToken: proxyToken,
		leases:     leases,
		entries:    make(map[string]*agentEntry),
	}
}

// activeJWTs returns the cache keys (cacheKey(jwt, scope)) of non-evicted sessions, so the lease store can
// stop refreshing leases whose agent session is gone.
func (a *agentCache) activeJWTs() map[string]struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	live := make(map[string]struct{}, len(a.entries))
	now := time.Now()
	for key, entry := range a.entries {
		if now.Sub(entry.lastSeen) <= agentInactiveTTL {
			live[key] = struct{}{}
		}
	}
	return live
}

func (a *agentCache) get(jwt string, scope agentScope) ([]*resolvedService, error) {
	key := cacheKey(jwt, scope)

	a.mu.Lock()
	entry := a.entries[key]
	if entry != nil {
		entry.lastSeen = time.Now()
		snapshot := entry.services
		a.mu.Unlock()
		return snapshot, nil
	}
	a.mu.Unlock()

	resolved, err := a.resolve(jwt, scope)
	if err != nil {
		return nil, err
	}

	entry = &agentEntry{
		jwt:      jwt,
		scope:    scope,
		services: resolved,
		lastSeen: time.Now(),
	}
	a.mu.Lock()
	a.evictIfFullLocked(key)
	a.entries[key] = entry
	a.mu.Unlock()
	return resolved, nil
}

// evictIfFullLocked makes room for a new entry when the cache is at capacity. Callers must hold a.mu.
// It first drops inactive entries (the same threshold refreshActive uses), then, if still full, evicts
// the least-recently-seen entry so active agents keep their cached credentials.
func (a *agentCache) evictIfFullLocked(incoming string) {
	if len(a.entries) < maxAgentCacheEntries {
		return
	}
	if _, replacing := a.entries[incoming]; replacing {
		return
	}
	now := time.Now()
	for key, entry := range a.entries {
		if now.Sub(entry.lastSeen) > agentInactiveTTL {
			delete(a.entries, key)
		}
	}
	for len(a.entries) >= maxAgentCacheEntries {
		var oldestKey string
		var oldest time.Time
		for key, entry := range a.entries {
			if oldestKey == "" || entry.lastSeen.Before(oldest) {
				oldestKey, oldest = key, entry.lastSeen
			}
		}
		delete(a.entries, oldestKey)
	}
}

func (a *agentCache) resolve(jwt string, scope agentScope) ([]*resolvedService, error) {
	agentClient := resty.New().SetAuthToken(jwt)
	listResp, err := api.CallListProxiedServices(agentClient, api.ListProxiedServicesRequest{
		ProjectID:   scope.projectID,
		Environment: scope.environment,
		SecretPath:  scope.secretPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to discover proxied services: %w", err)
	}

	secretValues, err := a.fetchSecretValues(scope)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret values: %w", err)
	}

	var services []*resolvedService
	for _, svc := range listResp.Services {
		if !svc.CanProxy {
			continue
		}
		rs := &resolvedService{
			name:         svc.Name,
			hostPatterns: parseHostPatterns(svc.HostPattern),
			isEnabled:    svc.IsEnabled,
		}
		for _, cred := range svc.Credentials {
			// dynamic-secret-backed credential: register a lease and defer value resolution to request time
			if cred.DynamicSecretName != "" {
				key := leaseKey{
					jwt:        jwt,
					scope:      scope,
					secretName: cred.DynamicSecretName,
					configHash: canonicalConfigHash(cred.DynamicSecretConfig),
				}
				a.leases.register(key, leaseSpec{projectSlug: listResp.ProjectSlug, config: cred.DynamicSecretConfig})
				rs.credentials = append(rs.credentials, resolvedCredential{
					role:          cred.Role,
					headerName:    cred.HeaderName,
					headerPrefix:  cred.HeaderPrefix,
					headerPurpose: cred.HeaderPurpose,
					placeholder:   cred.PlaceholderValue,
					surfaces:      cred.SubstitutionSurfaces,
					dynamic:       &dynamicCredentialRef{key: key, field: cred.DynamicSecretField},
				})
				continue
			}

			if cred.SecretKey == "" {
				continue
			}
			value, ok := secretValues[cred.SecretKey]
			if !ok {
				log.Warn().Msgf("proxied service %q references missing secret %q; skipping", svc.Name, cred.SecretKey)
				continue
			}
			rs.credentials = append(rs.credentials, resolvedCredential{
				role:          cred.Role,
				headerName:    cred.HeaderName,
				headerPrefix:  cred.HeaderPrefix,
				headerPurpose: cred.HeaderPurpose,
				placeholder:   cred.PlaceholderValue,
				surfaces:      cred.SubstitutionSurfaces,
				value:         value,
			})
		}
		services = append(services, rs)
	}
	return services, nil
}

func (a *agentCache) fetchSecretValues(scope agentScope) (map[string]string, error) {
	params := models.GetAllSecretsParameters{
		Environment:              scope.environment,
		WorkspaceId:              scope.projectID,
		SecretsPath:              scope.secretPath,
		UniversalAuthAccessToken: a.proxyToken(),
		ExpandSecretReferences:   true,
		IncludeImport:            true,
	}
	secrets, err := util.GetAllEnvironmentVariables(params, "")
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(secrets))
	for _, s := range secrets {
		values[s.Key] = s.Value
	}
	return values, nil
}

func (a *agentCache) refreshActive() {
	type refreshTarget struct {
		key   string
		jwt   string
		scope agentScope
	}

	a.mu.Lock()
	targets := make([]refreshTarget, 0, len(a.entries))
	for key, entry := range a.entries {
		if time.Since(entry.lastSeen) > agentInactiveTTL {
			delete(a.entries, key)
			continue
		}
		targets = append(targets, refreshTarget{key: key, jwt: entry.jwt, scope: entry.scope})
	}
	a.mu.Unlock()

	for _, t := range targets {
		resolved, err := a.resolve(t.jwt, t.scope)
		if err != nil {
			// Hard auth failure means the JWT was revoked/expired: evict to stop serving cached credentials (fail closed).
			if isAuthError(err) {
				log.Warn().Err(err).Msg("agent authorization no longer valid; dropping cached credentials")
				a.mu.Lock()
				delete(a.entries, t.key)
				a.mu.Unlock()
				continue
			}
			log.Warn().Err(err).Msg("failed to refresh agent cache")
			continue
		}
		a.mu.Lock()
		if entry, ok := a.entries[t.key]; ok {
			entry.services = resolved
		}
		a.mu.Unlock()
	}
}
