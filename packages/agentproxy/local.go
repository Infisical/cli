package agentproxy

import (
	"sync"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

// LocalOptions switches the proxy into local coupled mode (`agent-proxy run`): one developer, one
// sandboxed agent, one scope, for the lifetime of one wrapped command. In this mode the proxy accepts
// requests without Proxy-Authorization (the wire carries no credential at all; the child env must
// never hold a token), serves every request under the scope fixed here, and performs all Infisical
// API calls with the developer's own token.
type LocalOptions struct {
	ProjectID   string
	Environment string
	SecretPath  string

	// UserToken returns the developer's current access token (keyring login or INFISICAL_TOKEN).
	// It is called per API request so a refresher can rotate the token behind it.
	UserToken func() string

	// InfisicalHost is the hostname (no scheme/port) of the Infisical API. Egress to it through the
	// proxy is always refused: the control plane must stay unreachable from the sandbox as an
	// invariant, not merely because the child holds no token.
	InfisicalHost string

	// IdentityID and IdentityName label activity records; there is no wire JWT to decode them from.
	IdentityID   string
	IdentityName string
}

func (l *LocalOptions) scope() agentScope {
	return agentScope{projectID: l.ProjectID, environment: l.Environment, secretPath: l.SecretPath}
}

// localResolver is the local-mode counterpart of agentCache: a single snapshot of resolved services
// for the fixed startup scope instead of a keyed multi-agent cache. There is no entry map, eviction,
// or TTL bookkeeping because the one caller is known before the proxy starts. The snapshot refreshes
// on the poll loop and is dropped (fail closed) when the developer's authorization goes away.
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
	// One identity for discovery and value-fetch (the identity collapse), and no CanProxy filter:
	// locally the gate is Read Value alone, so a visible service whose secrets the developer can read
	// is brokered even without the Proxy permission.
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

// activeJWTs exists for the lease refresh loop; local mode never registers leases.
func (l *localResolver) activeJWTs() map[string]struct{} {
	return map[string]struct{}{}
}

// close drops the snapshot so credential values are unreachable; the next request must re-resolve
// (and fails if the developer's authorization is gone). Also the fail-closed path for refreshActive.
func (l *localResolver) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.services = nil
	l.valid = false
}
