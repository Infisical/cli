package agentproxy

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
)

const agentInactiveTTL = 10 * time.Minute

type resolvedCredential struct {
	role          string
	headerName    string
	headerPrefix  string
	headerPurpose string
	placeholder   string
	surfaces      []string
	value         string // real secret value resolved via the proxy's own MI
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
	cachedAt time.Time
}

// cacheKey scopes cached entries by both the agent JWT and the requested scope, so an agent
// connecting with a different environment/path does not reuse another scope's resolved credentials.
func cacheKey(jwt string, scope agentScope) string {
	return strings.Join([]string{jwt, scope.projectID, scope.environment, scope.secretPath}, "\x00")
}

// agentCache resolves and caches, per agent JWT, the proxied services the agent may use
// along with the real credential values (fetched with the proxy's own token).
type agentCache struct {
	proxyToken string

	mu      sync.Mutex
	entries map[string]*agentEntry
}

func newAgentCache(proxyToken string) *agentCache {
	return &agentCache{
		proxyToken: proxyToken,
		entries:    make(map[string]*agentEntry),
	}
}

// get returns a snapshot of the resolved services for the agent JWT + scope, resolving on first use.
// The returned slice is read by the caller without the cache lock, so it is snapshotted here
// under the lock to avoid a data race with refreshActive reassigning entry.services.
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
		cachedAt: time.Now(),
	}
	a.mu.Lock()
	a.entries[key] = entry
	a.mu.Unlock()
	return resolved, nil
}

// resolve discovers the agent's proxied services (using the agent JWT) and fills in the real
// secret values (using the proxy's own token).
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
			value, ok := secretValues[cred.SecretKey]
			if !ok {
				// stale reference: secret renamed/deleted after the service was created
				util.PrintWarning(fmt.Sprintf("proxied service %q references missing secret %q; skipping", svc.Name, cred.SecretKey))
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
		UniversalAuthAccessToken: a.proxyToken,
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

// refreshActive re-resolves cached agents that were seen recently and drops inactive ones.
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
			util.PrintWarning(fmt.Sprintf("failed to refresh agent cache: %v", err))
			continue
		}
		a.mu.Lock()
		if entry, ok := a.entries[t.key]; ok {
			entry.services = resolved
			entry.cachedAt = time.Now()
		}
		a.mu.Unlock()
	}
}
