package agentvault

import (
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

const (
	// The engine, the column, the API and the UI all say deny. The inherited constant was UnmatchedBlock;
	// renamed here, in a file written from scratch, so packages/agentproxy is untouched.
	UnmatchedAllow = "allow"
	UnmatchedDeny  = "deny"
)

type resolveResult struct {
	SessionID   string
	ExpiresAt   *time.Time
	Connections []*resolvedConnection
}

// infisicalResolver is the one implementation of sessionResolver. It exists as a seam so the cache can
// be tested without a server, not because a second implementation is planned — the in-process mode the
// old proxy had is deliberately not carried over.
type infisicalResolver struct {
	proxyToken func() string
}

func newInfisicalResolver(proxyToken func() string) *infisicalResolver {
	return &infisicalResolver{proxyToken: proxyToken}
}

func (r *infisicalResolver) resolve(sessionToken string) (*resolveResult, error) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return nil, err
	}
	httpClient.SetAuthToken(r.proxyToken())

	res, err := api.CallResolveAgentVaultSession(httpClient, sessionToken)
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
			// Parsed once here rather than per request.
			hostPatterns: parseHostPatterns(wire.HostPattern),
			credential:   toCredential(wire.Credential),
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
