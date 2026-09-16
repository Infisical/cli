package agentvault

import (
	"encoding/base64"
	"sort"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
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
	// nil when logging is off for this session.
	Activity *activityGrant
}

const activityKeyBytes = 32

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

func (r *infisicalResolver) resolve(sessionToken string, held *activityGrant) (*resolveResult, error) {
	res, err := api.CallResolveAgentVaultSession(r.client, sessionToken, api.ResolveAgentVaultSessionRequest{
		HasActivityKey: held != nil,
	})
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
			id:                  wire.ID,
			name:                wire.Name,
			accessBundleName:    wire.AccessBundleName,
			hostPatterns:        parseHostPatterns(wire.HostPattern),
			allowedMethods:      toMethodSet(wire.AllowedMethods),
			allowedPathPrefixes: toPathPrefixes(wire.AllowedPathPrefixes),
			credential:          toCredential(wire.Credential),
			customHeaders:       toCustomHeaders(wire.CustomHeaders),
			substitutions:       toSubstitutions(wire.Substitutions),
		})
	}

	return &resolveResult{
		SessionID: res.SessionID,
		ExpiresAt: expiresAt,
		Services:  services,
		Activity:  toActivityGrant(res.SessionID, res.Activity, held),
	}, nil
}

// toActivityGrant decides what the proxy records under after a poll.
//
// The key is sent exactly once per session. When we told the server we already hold it, the response
// carries no key and the cached one is carried forward; clearing it here instead would silently stop all
// logging after the very first poll. After any cache eviction the grant and the flag are dropped
// together, so the next resolve asks for the key again and this self-heals.
func toActivityGrant(sessionID string, wire api.AgentVaultActivityGrant, held *activityGrant) *activityGrant {
	if !wire.Enabled {
		return nil
	}
	if wire.ProjectID == "" {
		log.Warn().Str("sessionId", sessionID).Msg("agent-vault: activity is enabled but no project was named, not recording")
		return nil
	}

	if wire.SessionKey == "" {
		if held != nil {
			return &activityGrant{sessionID: sessionID, projectID: wire.ProjectID, key: held.key}
		}
		log.Warn().Str("sessionId", sessionID).Msg("agent-vault: activity is enabled but no key was sent, not recording")
		return nil
	}

	key, err := base64.StdEncoding.DecodeString(wire.SessionKey)
	if err != nil || len(key) != activityKeyBytes {
		log.Warn().Str("sessionId", sessionID).Msg("agent-vault: the activity key Infisical sent is unusable, not recording")
		return nil
	}

	return &activityGrant{sessionID: sessionID, projectID: wire.ProjectID, key: key}
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

func toMethodSet(methods []string) map[string]bool {
	if methods == nil {
		return nil
	}
	set := make(map[string]bool, len(methods))
	for _, method := range methods {
		set[strings.ToUpper(strings.TrimSpace(method))] = true
	}
	return set
}

// Normalised the same way the backend stores them, so a trailing slash cannot make a prefix unmatchable.
//
// Fails closed like toMethodSet: nil means unrestricted, and anything else means restricted, including a
// list the server sent with nothing usable in it. Dropping to a zero-length slice there would read as
// unrestricted at every call site, which is the opposite of what a restriction that arrived empty means.
func toPathPrefixes(prefixes []string) []string {
	if prefixes == nil {
		return nil
	}
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix != "/" {
			prefix = strings.TrimRight(prefix, "/")
		}
		// After the trim, so an all-slashes prefix cannot arrive here as "" and match every path.
		if prefix == "" {
			continue
		}
		out = append(out, prefix)
	}
	if len(out) == 0 {
		// A prefix no request can match, so a restriction the server sent empty allows nothing.
		return []string{"\x00"}
	}
	return out
}

func toCustomHeaders(wire []api.AgentVaultCustomHeader) []customHeader {
	if len(wire) == 0 {
		return nil
	}
	customHeaders := make([]customHeader, 0, len(wire))
	for _, h := range wire {
		customHeaders = append(customHeaders, customHeader{name: h.Name, prefix: h.Prefix, value: []byte(h.Value)})
	}
	return customHeaders
}

func toSubstitutions(wire []api.AgentVaultSubstitution) []substitution {
	if len(wire) == 0 {
		return nil
	}
	subs := make([]substitution, 0, len(wire))
	for _, s := range wire {
		surfaces := make(map[string]bool, len(s.Surfaces))
		for _, surface := range s.Surfaces {
			surfaces[surface] = true
		}
		subs = append(subs, substitution{placeholder: s.Placeholder, surfaces: surfaces, value: []byte(s.Value)})
	}
	// Longest first, so a placeholder that starts with another one is swapped before the shorter one can
	// eat its prefix and leave the tail behind. Sorted here rather than per request: the slice is shared by
	// every request the session serves.
	sort.SliceStable(subs, func(i, j int) bool {
		return len(subs[i].placeholder) > len(subs[j].placeholder)
	})
	return subs
}
