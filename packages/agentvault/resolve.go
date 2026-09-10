package agentvault

import (
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
)

const (
	// The engine, the column, the API and the UI all say deny; the inherited constant was UnmatchedBlock.
	UnmatchedAllow = "allow"
	UnmatchedDeny  = "deny"
)

type resolveResult struct {
	SessionID   string
	ExpiresAt   *time.Time
	Connections []*resolvedConnection
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

	connections := make([]*resolvedConnection, 0, len(res.Connections))
	for _, wire := range res.Connections {
		connections = append(connections, &resolvedConnection{
			id:               wire.ID,
			name:             wire.Name,
			accessBundleName: wire.AccessBundleName,
			hostPatterns:     parseHostPatterns(wire.HostPattern),
			credential:       toCredential(wire.Credential),
		})
	}

	return &resolveResult{SessionID: res.SessionID, ExpiresAt: expiresAt, Connections: connections}, nil
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
