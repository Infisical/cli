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

type resolvedCredential struct {
	role          string
	headerName    string
	headerPrefix  string
	headerPurpose string
	placeholder   string
	surfaces      []string
	value         string
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

	mu      sync.Mutex
	entries map[string]*agentEntry
}

func newAgentCache(proxyToken func() string) *agentCache {
	return &agentCache{
		proxyToken: proxyToken,
		entries:    make(map[string]*agentEntry),
	}
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
	a.entries[key] = entry
	a.mu.Unlock()
	return resolved, nil
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
