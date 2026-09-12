package agentvault

import (
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
)

const (
	// The column, the API and the UI all use these two words, so the proxy compares them verbatim.
	TrafficPolicyAnyHost     = "any-host"
	TrafficPolicyBundleHosts = "bundle-hosts"
)

type resolveResult struct {
	SessionID string
	ExpiresAt *time.Time
	Services  []*resolvedService
}

// A seam so the cache can be tested without a server, not because a second implementation is expected.
type infisicalResolver struct {
	client *resty.Client
}

// One client for the life of the proxy, so resolves share a connection pool instead of paying a TLS
// handshake each. Retries are off: a resolve runs while an agent's request waits, and a 429 means
// "later", which the poll loop already provides once an interval. The token is fixed for the run.
func newInfisicalResolver(proxyToken func() string) (*infisicalResolver, error) {
	client, err := util.GetRestyClientWithPolicy(util.RetryPolicy{})
	if err != nil {
		return nil, err
	}
	client.SetAuthToken(proxyToken()).SetTimeout(controlPlaneTimeout)
	return &infisicalResolver{client: client}, nil
}

func (r *infisicalResolver) resolve(sessionToken string) (*resolveResult, error) {
	res, err := api.CallResolveAgentVaultSession(r.client, sessionToken)
	if err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if res.ExpiresAt != "" {
		if parsed, parseErr := time.Parse(time.RFC3339, res.ExpiresAt); parseErr == nil {
			expiresAt = &parsed
		}
	}

	services := make([]*resolvedService, 0, len(res.Services))
	for _, wire := range res.Services {
		services = append(services, &resolvedService{
			id:               wire.ID,
			name:             wire.Name,
			accessBundleName: wire.AccessBundleName,
			hostPatterns:     parseHostPatterns(wire.HostPattern),
			credential:       toCredential(wire.Credential),
		})
	}

	return &resolveResult{SessionID: res.SessionID, ExpiresAt: expiresAt, Services: services}, nil
}

func toCredential(wire api.AgentVaultCredential) credential {
	switch wire.Type {
	case credentialBearer:
		return credential{
			kind:         credentialBearer,
			headerName:   wire.HeaderName,
			headerPrefix: wire.HeaderPrefix,
			value:        []byte(wire.Value),
		}
	case credentialBasic:
		return credential{
			kind:     credentialBasic,
			username: wire.Username,
			password: []byte(wire.Password),
		}
	default:
		return credential{kind: credentialPassthrough}
	}
}
