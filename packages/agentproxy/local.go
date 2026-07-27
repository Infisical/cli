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

	// CADir, if set, persists the local root CA there (reused across runs and trustable in the OS
	// trust store) instead of a fresh in-memory root. Must be a sandbox-denied path so the agent
	// cannot read the key.
	CADir string

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
	opts   *LocalOptions
	leases *leaseStore

	mu       sync.Mutex
	services []*resolvedService
	valid    bool

	// noLeaseWarned remembers which dynamic secrets have already been reported as unleasable, so the
	// warning is not repeated on every poll-interval refresh.
	noLeaseWarned map[string]bool
}

func newLocalResolver(opts *LocalOptions, leases *leaseStore) *localResolver {
	return &localResolver{opts: opts, leases: leases}
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
		registerDynamic: func(cred api.ProxiedServiceCredential, projectSlug string) *dynamicCredentialRef {
			// CallerCanLease is the developer's own Lease permission on this dynamic secret, and locally
			// the developer is the minter, so it is the gate. Skipping here with one clear warning beats
			// registering a lease that can never be minted and then failing on every request.
			//
			// Note this reads the opposite way from `connect`, where the same flag being true is a
			// misconfiguration: there the agent is a different identity, and an agent that can lease a
			// brokered dynamic secret could bypass the proxy entirely. Locally there is no second
			// identity to separate, and the sandbox is what stops the agent minting for itself.
			if !cred.CallerCanLease {
				l.warnUnleasable(cred.DynamicSecretName)
				return nil
			}

			// Leases are minted and renewed with the developer's own token, the same one used for
			// discovery and static values. leaseKey.jwt stays empty because local mode carries no wire
			// credential; the scope alone identifies the single caller, and activeJWTs derives the
			// matching liveness key from it.
			key := leaseKey{
				scope:      l.opts.scope(),
				secretName: cred.DynamicSecretName,
				configHash: canonicalConfigHash(cred.DynamicSecretConfig),
			}
			l.leases.register(key, leaseSpec{projectSlug: projectSlug, config: cred.DynamicSecretConfig})
			return &dynamicCredentialRef{key: key, field: cred.DynamicSecretField}
		},
	})
}

// warnUnleasable reports a dynamic secret the developer has no Lease permission for, once per secret.
func (l *localResolver) warnUnleasable(name string) {
	l.mu.Lock()
	if l.noLeaseWarned == nil {
		l.noLeaseWarned = map[string]bool{}
	}
	already := l.noLeaseWarned[name]
	l.noLeaseWarned[name] = true
	l.mu.Unlock()
	if already {
		return
	}
	log.Warn().Msgf("skipping dynamic secret %q: your account cannot create leases for it, so that credential cannot be brokered. Ask for the Lease permission on this dynamic secret.", name)
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

// activeJWTs tells the lease refresh loop which leases are still live. Local mode has exactly one
// caller, so this is the single key derived from the empty wire JWT plus the fixed scope, matching the
// leaseKey registered in resolveSnapshot. It reports nothing while the snapshot is invalid, so a
// dropped authorization stops lease renewal as well as credential serving.
func (l *localResolver) activeJWTs() map[string]struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.valid {
		return map[string]struct{}{}
	}
	return map[string]struct{}{cacheKey("", l.opts.scope()): {}}
}

// close drops the snapshot (fail closed); the next request must re-resolve.
func (l *localResolver) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.services = nil
	l.valid = false
}
