package agentproxy

import (
	"sync"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

// LocalOptions switches the proxy into local coupled mode (`agent-proxy run`): one developer, one
// agent, one scope. Requests carry no Proxy-Authorization; every request uses the scope and token
// fixed here, and API calls use the developer's own token.
type LocalOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string

	// UserToken returns the developer's current access token; called per request so it can rotate.
	UserToken func() string

	// InfisicalHost (bare hostname) is always refused through the proxy, keeping the control plane
	// unreachable from the sandbox as an invariant, not just because the child holds no token.
	InfisicalHost string

	// IdentityID/IdentityName label activity records (no wire JWT to decode them from).
	IdentityID   string
	IdentityName string
}

func (l *LocalOptions) scope() agentScope {
	return agentScope{projectID: l.ProjectID, environment: l.Environment, secretPath: l.SecretPath}
}

// localResolver is the single-snapshot, single-scope counterpart of agentCache (no keyed map, since
// the one caller is fixed at startup). The snapshot refreshes on the poll loop and is dropped
// (fail closed) when the developer's authorization goes away.
type localResolver struct {
	opts *LocalOptions

	mu       sync.Mutex
	services []*resolvedService
	valid    bool

	dynamicWarned bool
}

func newLocalResolver(opts *LocalOptions) *localResolver {
	return &localResolver{opts: opts}
}

func (l *localResolver) get(_ string, _ agentScope) ([]*resolvedService, error) {
	l.mu.Lock()
	if l.valid {
		snapshot := l.services
		l.mu.Unlock()
		return snapshot, nil
	}
	l.mu.Unlock()

	resolved, err := l.resolveSnapshot()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.services = resolved
	l.valid = true
	l.mu.Unlock()
	return resolved, nil
}

func (l *localResolver) resolveSnapshot() ([]*resolvedService, error) {
	// One identity for discovery and value-fetch, and no CanProxy filter: locally the gate is Read
	// Value alone.
	token := l.opts.UserToken()
	return resolveServices(l.opts.scope(), resolveParams{
		discoveryToken:      token,
		valueToken:          func() string { return token },
		includeNonProxyable: true,
		registerDynamic: func(cred api.ProxiedServiceCredential, _ string) *dynamicCredentialRef {
			l.mu.Lock()
			warned := l.dynamicWarned
			l.dynamicWarned = true
			l.mu.Unlock()
			if !warned {
				log.Warn().Msgf("proxied service references dynamic secret %q; dynamic secrets are not supported in local mode, skipping those credentials", cred.DynamicSecretName)
			}
			return nil
		},
	})
}

func (l *localResolver) identity(_ string, _ agentScope) (string, string, bool) {
	return l.opts.IdentityID, l.opts.IdentityName, true
}

func (l *localResolver) refreshActive() {
	l.mu.Lock()
	haveSnapshot := l.valid
	l.mu.Unlock()
	if !haveSnapshot {
		return
	}

	resolved, err := l.resolveSnapshot()
	if err != nil {
		if isAuthError(err) {
			log.Warn().Err(err).Msg("developer authorization no longer valid; dropping brokered credentials")
			l.close()
			return
		}
		log.Warn().Err(err).Msg("failed to refresh brokered credentials; keeping the previous snapshot")
		return
	}
	l.mu.Lock()
	l.services = resolved
	l.valid = true
	l.mu.Unlock()
}

// activeJWTs is for the lease loop; local mode registers no leases.
func (l *localResolver) activeJWTs() map[string]struct{} {
	return map[string]struct{}{}
}

// close drops the snapshot (fail closed); the next request must re-resolve.
func (l *localResolver) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.services = nil
	l.valid = false
}
