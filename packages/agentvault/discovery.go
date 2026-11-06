package agentvault

import (
	"encoding/json"
	"net/http"
	"strings"
)

// DiscoveryHost is the reserved name the proxy answers for the session a request arrives on: the session's services and
// skills, forwarded to the proxy's own Infisical with the session's own token, so the agent never handles its token and
// needs no address for Infisical. .invalid can never resolve (RFC 6761): the proxy never answers for a host it should be
// proxying, and outside a proxy the request fails at once at DNS.
const DiscoveryHost = "agent-vault.invalid"

// BuiltinSkillName is the skill Infisical adds to every session's skills, which tells an agent how to work behind the
// proxy. agent-vault run leaves it out when told to.
const BuiltinSkillName = "infisical-agent-vault"

// ServicesURLEnv is set by agent-vault run for scripts and tools. The built-in skill doesn't read it: some agents blank
// variables in piped shell commands, and a sandbox started without agent-vault run has none.
const ServicesURLEnv = "INFISICAL_AGENT_VAULT_SERVICES_URL"

// DiscoveryURL is https, so nobody on the way to the proxy can change the list the agent follows. The proxy accepts the
// CONNECT for this name before it checks the session, so a refused session still reads as JSON rather than as a
// failed CONNECT. Plain http reaches the same list.
const DiscoveryURL = "https://" + DiscoveryHost + "/services"

// Set on every response to a request the proxy forwarded or refused, after the upstream's headers are copied, so
// an upstream cannot set them itself.
const (
	HeaderDecision = "X-Agent-Vault-Decision"
	HeaderService  = "X-Agent-Vault-Service"
)

func isDiscoveryHost(hostname string) bool {
	return strings.EqualFold(strings.TrimSuffix(hostname, "."), DiscoveryHost)
}

type proxyErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeProxyError answers a request the proxy itself refused or could not complete. The message is the same fixed
// text the proxy always sent; the code and hint are for an agent deciding what to do next.
func writeProxyError(w http.ResponseWriter, status int, decision, code, message string) {
	w.Header().Set(HeaderDecision, decision)
	writeJSON(w, status, proxyErrorBody{Error: code, Message: message, Hint: proxyErrorHints[code]})
}

const (
	errorCodeSessionInvalid       = "session_invalid"
	errorCodeProxyRevoked         = "proxy_revoked"
	errorCodeSessionUnresolvable  = "session_unresolvable"
	errorCodePolicyBlocked        = "policy_blocked"
	errorCodeHostNotAllowed       = "host_not_allowed"
	errorCodeBadRequest           = "bad_request"
	errorCodePrivateDestination   = "private_destination"
	errorCodeUpstreamUnreachable  = "upstream_unreachable"
	errorCodeNotFound             = "not_found"
	errorCodeMethodNotAllowed     = "method_not_allowed"
	errorCodeBusy                 = "busy"
	errorCodeInfisicalUnreachable = "infisical_unreachable"
)

var proxyErrorHints = map[string]string{
	errorCodeSessionInvalid: "This is the Agent Vault proxy, not the API: the session this agent runs on has expired or been revoked, " +
		"or it belongs to a different Agent Vault project than this proxy, so every request is refused. The user has to start a new " +
		"session, or use a proxy in the session's project; nothing in this environment can fix it.",
	errorCodeProxyRevoked: "This is the Agent Vault proxy, not the API: an admin revoked this proxy's access, so it cannot broker " +
		"requests until its token is rotated.",
	errorCodeSessionUnresolvable: "The Agent Vault proxy could not reach Infisical to load this session. Try again in a moment.",
	errorCodePolicyBlocked: "This is the Agent Vault proxy, not the API: the service's rules do not allow this request, so a different " +
		"key will not help. " + DiscoveryURL + " lists what each service allows.",
	errorCodeHostNotAllowed: "This is the Agent Vault proxy, not the API: it only lets through hosts a service in this session covers. " +
		DiscoveryURL + " lists them.",
	errorCodePrivateDestination:   "This is the Agent Vault proxy, not the API: it does not let this door reach private or internal addresses.",
	errorCodeUpstreamUnreachable:  "The Agent Vault proxy could not reach the API. Try again in a moment.",
	errorCodeNotFound:             "This is the Agent Vault proxy. " + DiscoveryURL + " lists the services this session can use.",
	errorCodeBusy:                 "Too many agents are starting through this Agent Vault proxy at once. Try again in a moment.",
	errorCodeInfisicalUnreachable: "The Agent Vault proxy could not reach Infisical to answer this. Try again in a moment.",
}
