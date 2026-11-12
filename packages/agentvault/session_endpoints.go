package agentvault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// Variables so tests can shorten them.
var (
	// Under the 30 seconds agent-vault run waits for skills, so its own message about the wait wins. The wait for a
	// free slot, and passing the answer on, count against it too.
	sessionForwardTimeout = 25 * time.Second
	// Infisical caps one skill at 1 MB, and a bundle holds at most 25.
	sessionForwardMaxBytes int64 = 64 << 20
)

const (
	// Sent to Infisical with each forwarded request, so the services list can describe this proxy's traffic policy.
	headerProxyID      = "X-Agent-Vault-Proxy-Id"
	headerProxyVersion = "X-Agent-Vault-Proxy-Version"
)

// IsInfisicalForwardRefusal reports whether an error code from a session endpoint is the proxy's own answer rather than
// Infisical's answer passed on, so the CLI doesn't put it on Infisical.
func IsInfisicalForwardRefusal(code string) bool {
	return code == errorCodeBusy || code == errorCodeInfisicalUnreachable ||
		code == errorCodeProxyRevoked || code == errorCodeSessionUnresolvable
}

// IsTransientSessionRefusal reports whether an error code is the proxy failing to look the session up for a moment, such as
// on a 429 or a dropped connection, which it doesn't remember and asking again can clear.
func IsTransientSessionRefusal(code string) bool {
	return code == errorCodeSessionUnresolvable
}

// IsSessionRefusal reports whether an error code is the proxy refusing the session itself, which only a new session fixes.
func IsSessionRefusal(code string) bool {
	return code == errorCodeSessionInvalid
}

// A process runs one proxy, and starting agents is bursty, so a fixed number of requests to Infisical at once keeps a
// burst from holding open a connection per agent. The rest wait their turn rather than fail.
var sessionForwardSlots = make(chan struct{}, 8)

// Nothing about a session stays on the client: the session's token goes on each request, and with no cookie jar, a
// cookie on one session's answer isn't sent with the next session's request. It follows no redirect, so the proxy only
// ever passes on Infisical's own answer to the paths it allows.
func newSessionEndpointClient() (*resty.Client, error) {
	client, err := util.GetRestyClientWithPolicy(util.RetryPolicy{})
	if err != nil {
		return nil, err
	}
	return client.SetCookieJar(nil).SetRedirectPolicy(resty.NoRedirectPolicy()), nil
}

// One client for the life of the proxy, so forwarded requests share a connection pool instead of each opening its own
// and leaving it idle. A variable so tests can point it at a stand-in for Infisical.
var sessionEndpointClient = sync.OnceValues(newSessionEndpointClient)

var errSessionAnswerTooLarge = errors.New("Infisical's answer is larger than the proxy passes on")

type sessionRoute struct {
	// Under config.INFISICAL_URL, which ends in /api.
	infisicalPath string
	decision      string
	forwardQuery  bool
}

// The only requests the proxy answers for the session: these session endpoints of its own Infisical, on the host, port
// and API path from --domain. Every other request to that host goes through like any other, so an agent prompted to send
// data elsewhere can't use the session's token as a way out. The scheme on the agent's side doesn't matter, because the
// proxy calls Infisical itself: agent-vault run asks over TLS even when --domain is http, so it can check the answer
// against the proxy's certificate authority.
func sessionRouteFor(t tunnel, path string) (sessionRoute, bool) {
	target, ok := proxyInfisicalTarget()
	if !ok || !target.covers(t.hostname, t.port) {
		return sessionRoute{}, false
	}
	switch path {
	case target.apiPath + sessionServicesPath:
		return sessionRoute{infisicalPath: sessionServicesPath, decision: decisionDiscovery}, true
	case target.apiPath + sessionSkillsPath:
		return sessionRoute{infisicalPath: sessionSkillsPath, decision: decisionSkills, forwardQuery: true}, true
	}
	return sessionRoute{}, false
}

// serveSessionEndpoint answers a request for one of the session's endpoints on the session the tunnel carries. The session
// is checked here rather than at the door, so a refused session's reason arrives as JSON, inside TLS for https.
func (ps *proxyServer) serveSessionEndpoint(w http.ResponseWriter, r *http.Request, t tunnel, route sessionRoute) {
	found, err := ps.cache.lookup(t.sessionToken, nil)
	if err != nil {
		refusal := classifyGateRefusal(err)
		refusal.event.Str("host", t.hostname).Str("sessionKey", sessionKey(t.sessionToken)).Str("decision", refusal.decision).
			Int("status", refusal.status).Msg(refusal.msg)
		writeProxyError(w, refusal.status, refusal.decision, refusal.code, refusal.body)
		return
	}

	status, decision, brokeOff := ps.forwardSessionRequest(w, r, t.sessionToken, route)

	method, path := truncateLogged(r.Method, maxLoggedMethodLen), truncatePath(requestPath(r))
	log.Info().Str("method", method).Str("host", t.hostname).Str("path", path).Str("decision", decision).
		Int("status", status).Msg("agent-vault: request")
	ps.sessionLogs.record(found.sessionLog, sessionLogRecord{
		Method:   method,
		Host:     t.hostname,
		Port:     t.port,
		Path:     path,
		Status:   status,
		Decision: decision,
	})
	// The status line is already on the wire, so dropping the connection is the only way left to show the agent that
	// the answer is incomplete. Returning would have net/http end the body as if it were whole.
	if brokeOff {
		panic(http.ErrAbortHandler)
	}
}

// brokeOff reports an answer that stopped part way after its status went out.
func (ps *proxyServer) forwardSessionRequest(w http.ResponseWriter, r *http.Request, sessionToken string, route sessionRoute) (status int, decision string, brokeOff bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProxyError(w, http.StatusMethodNotAllowed, decisionBlocked, errorCodeMethodNotAllowed, "this address only answers GET")
		return http.StatusMethodNotAllowed, decisionBlocked, false
	}

	ctx, cancel := context.WithTimeout(r.Context(), sessionForwardTimeout)
	defer cancel()
	select {
	case sessionForwardSlots <- struct{}{}:
		defer func() { <-sessionForwardSlots }()
	case <-ctx.Done():
		if r.Context().Err() == nil {
			writeProxyError(w, http.StatusServiceUnavailable, decisionError, errorCodeBusy,
				"too many agents are starting through the proxy at once. Try again in a moment")
		}
		return http.StatusServiceUnavailable, decisionError, false
	}

	resp, err := ps.callInfisical(ctx, r.Method, route, r.URL.RawQuery, sessionToken)
	if err != nil {
		log.Warn().Err(err).Str("sessionKey", sessionKey(sessionToken)).Str("path", route.infisicalPath).
			Msg("agent-vault: could not reach Infisical for the session")
		writeProxyError(w, http.StatusBadGateway, decisionError, errorCodeInfisicalUnreachable,
			"the proxy could not reach Infisical")
		return http.StatusBadGateway, decisionError, false
	}
	defer resp.RawBody().Close()

	w.Header().Set(HeaderDecision, route.decision)
	// Inside TLS this vouches for the URL the CONNECT answer named in the clear.
	if apiURL := proxyAPIURL(); apiURL != "" {
		w.Header().Set(HeaderAPIURL, apiURL)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// A busy Infisical says when to ask again, which agent-vault run's retries wait for.
	if retryAfter := resp.Header().Get("Retry-After"); retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	// Passed on so a client can also tell an answer that stopped short from a whole one.
	if length := resp.RawResponse.ContentLength; length >= 0 && length <= sessionForwardMaxBytes {
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	}
	// The slot is held until the answer is out, so a client that stops reading must not keep it past the request's own
	// deadline. The tunnel's write timeout is half an hour.
	if deadline, ok := ctx.Deadline(); ok {
		_ = http.NewResponseController(w).SetWriteDeadline(deadline)
	}
	w.WriteHeader(resp.StatusCode())
	if r.Method != http.MethodGet {
		return resp.StatusCode(), route.decision, false
	}

	copied, err := io.Copy(w, io.LimitReader(resp.RawBody(), sessionForwardMaxBytes+1))
	if err == nil && copied > sessionForwardMaxBytes {
		err = errSessionAnswerTooLarge
	}
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Warn().Err(err).Str("sessionKey", sessionKey(sessionToken)).Msg("agent-vault: passing on Infisical's answer failed part way")
		}
		return resp.StatusCode(), route.decision, true
	}
	return resp.StatusCode(), route.decision, false
}

// The session's own token is the only credential sent, whatever the agent put in its Authorization header, so an agent
// handed someone else's token can't use these endpoints to act as that session.
func (ps *proxyServer) callInfisical(ctx context.Context, method string, route sessionRoute, rawQuery, sessionToken string) (*resty.Response, error) {
	client, err := sessionEndpointClient()
	if err != nil {
		return nil, err
	}
	req := client.R().
		SetContext(ctx).
		SetDoNotParseResponse(true).
		SetAuthToken(sessionToken).
		SetHeader("User-Agent", api.USER_AGENT).
		SetHeader("Accept", "application/json").
		SetHeader(headerProxyVersion, util.CLI_VERSION)
	if ps.opts.ProxyID != "" {
		req.SetHeader(headerProxyID, ps.opts.ProxyID)
	}
	if route.forwardQuery && rawQuery != "" {
		req.SetQueryString(rawQuery)
	}
	resp, err := req.Execute(method, fmt.Sprintf("%v%s", config.INFISICAL_URL, route.infisicalPath))
	if err != nil {
		return nil, err
	}
	return resp, nil
}
