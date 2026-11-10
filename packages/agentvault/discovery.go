package agentvault

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
)

// BuiltinSkillName is the skill Infisical adds to every session's skills, which tells an agent how to work behind the
// proxy. agent-vault run leaves it out when told to.
const BuiltinSkillName = "infisical-agent-vault"

// HeaderAPIURL names the Infisical API this proxy works with. The proxy sends it only to a session it accepts, on its
// CONNECT answer, its own refusals and the session endpoints' answers, so agent-vault run can point the agent at those
// endpoints, through the proxy. It never passes on a host's own.
const HeaderAPIURL = "X-Agent-Vault-Api-Url"

// URLEnv holds the URL of the proxy's Infisical in the agent's environment, such as https://app.infisical.com, the
// same URL as --domain: agent-vault run sets it once the proxy's header is confirmed, and code that starts agents itself
// sets it to what it passed the proxy. The agent reaches its session's endpoints under <URL>/api, through the proxy.
const URLEnv = "INFISICAL_AGENT_VAULT_URL"

// InfisicalURL is the URL an agent gets in URLEnv for apiURL, or "" if apiURL doesn't end in /api, since the agent adds
// /api itself.
func InfisicalURL(apiURL string) string {
	if !strings.HasSuffix(apiURL, "/api") {
		return ""
	}
	return strings.TrimSuffix(apiURL, "/api")
}

// Under the API URL. Through the proxy, the agent reaches these with its session's own token, which it never holds.
const (
	sessionServicesPath = "/v1/agent-vault/session/services"
	sessionSkillsPath   = "/v1/agent-vault/session/skills"
)

// Set on every response to a request the proxy forwarded or refused, after the upstream's headers are copied, so
// an upstream cannot set them itself.
const (
	HeaderDecision = "X-Agent-Vault-Decision"
	HeaderService  = "X-Agent-Vault-Service"
	// The code of a refusal the proxy wrote, such as session_invalid, also on a CONNECT answer that opens a tunnel for a
	// refused session, so agent-vault run can say why without reading a body.
	HeaderError = "X-Agent-Vault-Error"
)

// The decisions only the proxy's own session endpoints set.
const (
	DecisionDiscovery = decisionDiscovery
	DecisionSkills    = decisionSkills
)

// proxyAPIURL is the Infisical API this proxy works with, from --domain, or "" if that isn't a URL the proxy can name in
// a header. Agents see it in headers and hints, so credentials, a query or a fragment in --domain are left out.
func proxyAPIURL() string {
	parsed, err := url.Parse(strings.TrimSuffix(config.INFISICAL_URL, "/"))
	if err != nil {
		return ""
	}
	parsed.User, parsed.RawQuery, parsed.ForceQuery, parsed.Fragment, parsed.RawFragment = nil, "", false, "", ""
	return publishableAPIURL(parsed)
}

// publishableAPIURL is the URL as an agent may be given it, or "" if it isn't an http(s) URL without credentials,
// query, fragment or control characters.
func publishableAPIURL(parsed *url.URL) string {
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return ""
	}
	apiURL := strings.TrimSuffix(parsed.String(), "/")
	if strings.ContainsFunc(apiURL, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return ""
	}
	return apiURL
}

// ErrProxyRefusedSession is AskProxyAPIURL's answer from a proxy that refused the session, or couldn't check it, and so
// named no Infisical. Unlike an answer without any Agent Vault header, it doesn't mean the proxy is too old. The error
// returned is a *ProxyRefusalError that matches it.
var ErrProxyRefusedSession = errors.New("the proxy refused the session, so it named no Infisical")

// ProxyRefusalError is a proxy's refusal of the session on its CONNECT answer. Code is the proxy's error code, empty
// from a proxy that marked the refusal without one.
type ProxyRefusalError struct {
	Code string
}

func (e *ProxyRefusalError) Error() string {
	if message := sessionRefusalMessages[e.Code]; message != "" {
		return message
	}
	return "the proxy refused the session"
}

func (e *ProxyRefusalError) Is(target error) bool { return target == ErrProxyRefusedSession }

// The fixed text the proxy sends with each refusal of the session itself.
var sessionRefusalMessages = map[string]string{
	errorCodeSessionInvalid:      "the session is no longer valid, or it belongs to a different Agent Vault project than this proxy",
	errorCodeProxyRevoked:        proxyRevokedBody,
	errorCodeSessionUnresolvable: "the proxy could not reach Infisical to load the session",
}

const maxConnectAnswerBytes = 64 << 10

// AskProxyAPIURL asks the proxy at proxyAddr which Infisical it works with. It opens a CONNECT for target with the
// session's token, reads the proxy's answer, and closes the connection without sending anything through it. A proxy too
// old to say answers without the header, and "" comes back.
//
// The answer crosses the network in the clear, so it is only a claim: use it once an answer from inside TLS, checked
// against the proxy's certificate authority, names the same URL (the session endpoints' answers carry it too).
func AskProxyAPIURL(ctx context.Context, proxyAddr, sessionToken, target string) (string, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	// A deadline alone wouldn't end a read when ctx is cancelled, such as by Ctrl-C while the proxy looks the session up.
	defer context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })()

	auth := base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername + ":" + sessionToken))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, auth); err != nil {
		return "", err
	}
	// Only the head is read: closing the body would wait for the tunnel to end, and the connection is closed instead.
	// http.ReadResponse sets no limit of its own, and this answer crosses the network in the clear, so anyone on the way
	// could otherwise send an endless head. The proxy's answer is a status line and a few headers.
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, maxConnectAnswerBytes)), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return "", err
	}

	claimed := APIURLFromHeader(resp.Header.Get(HeaderAPIURL))
	if claimed == "" && IsProxyRefusal(resp.Header.Get(HeaderDecision)) {
		return "", &ProxyRefusalError{Code: resp.Header.Get(HeaderError)}
	}
	return claimed, nil
}

// APIURLFromHeader is the API URL a proxy named in HeaderAPIURL, or "" if it isn't one an agent may be given.
func APIURLFromHeader(value string) string {
	parsed, err := url.Parse(strings.TrimSuffix(value, "/"))
	if err != nil {
		return ""
	}
	return publishableAPIURL(parsed)
}

// infisicalTarget is where the agent reaches the proxy's own Infisical through the proxy.
type infisicalTarget struct {
	hostname string
	port     string
	apiPath  string
}

func proxyInfisicalTarget() (infisicalTarget, bool) {
	parsed, err := url.Parse(proxyAPIURL())
	if err != nil || parsed.Host == "" {
		return infisicalTarget{}, false
	}
	port := parsed.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[parsed.Scheme]
	}
	return infisicalTarget{
		hostname: strings.TrimSuffix(strings.ToLower(parsed.Hostname()), "."),
		port:     port,
		apiPath:  strings.TrimSuffix(parsed.Path, "/"),
	}, true
}

func (target infisicalTarget) covers(hostname, port string) bool {
	return strings.EqualFold(strings.TrimSuffix(hostname, "."), target.hostname) && port == target.port
}

// isProxyInfisicalHost reports whether hostname and port are the proxy's own Infisical.
func isProxyInfisicalHost(hostname, port string) bool {
	target, ok := proxyInfisicalTarget()
	return ok && target.covers(hostname, port)
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
	w.Header().Set(HeaderError, code)
	// A caller whose session the proxy refused, or couldn't check, learns nothing about where its Infisical is.
	if apiURL := proxyAPIURL(); apiURL != "" && !refusesSession(code) {
		w.Header().Set(HeaderAPIURL, apiURL)
	}
	writeJSON(w, status, proxyErrorBody{Error: code, Message: message, Hint: proxyErrorHint(code)})
}

// refusesSession reports whether a refusal with code is about the session itself, which no check has shown valid.
func refusesSession(code string) bool {
	return code == errorCodeSessionInvalid || code == errorCodeSessionUnresolvable || code == errorCodeProxyRevoked
}

// IsProxyRefusal reports whether decision marks an answer the proxy wrote itself rather than one it passed on.
func IsProxyRefusal(decision string) bool {
	return decision == decisionBlocked || decision == decisionError
}

// Stands for the URL of the session's services list, which only the running proxy knows.
const servicesURLPlaceholder = "{services}"

func proxyErrorHint(code string) string {
	hint := proxyErrorHints[code]
	if !strings.Contains(hint, servicesURLPlaceholder) {
		return hint
	}
	servicesURL := "$" + URLEnv + "/api" + sessionServicesPath
	if apiURL := proxyAPIURL(); apiURL != "" {
		servicesURL = apiURL + sessionServicesPath
	}
	return strings.ReplaceAll(hint, servicesURLPlaceholder, servicesURL)
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
		"key will not help. " + servicesURLPlaceholder + " lists what each service allows.",
	errorCodeHostNotAllowed: "This is the Agent Vault proxy, not the API: it only lets through hosts a service in this session covers. " +
		servicesURLPlaceholder + " lists them.",
	errorCodePrivateDestination:   "This is the Agent Vault proxy, not the API: it does not let this door reach private or internal addresses.",
	errorCodeUpstreamUnreachable:  "The Agent Vault proxy could not reach the API. Try again in a moment.",
	errorCodeBusy:                 "Too many agents are starting through this Agent Vault proxy at once. Try again in a moment.",
	errorCodeInfisicalUnreachable: "The Agent Vault proxy could not reach Infisical to answer this. Try again in a moment.",
}
