package agentvault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	// Under the 30 seconds agent-vault run waits for skills, so its own message about the wait wins. The wait for a
	// free slot counts against it too.
	reservedForwardTimeout = 25 * time.Second
	// Infisical caps one skill at 1 MB, and a bundle holds at most 25.
	reservedForwardMaxBytes = 64 << 20

	// Sent to Infisical with each forwarded request, so the services list can describe this proxy's traffic policy.
	headerProxyID      = "X-Agent-Vault-Proxy-Id"
	headerProxyVersion = "X-Agent-Vault-Proxy-Version"
)

// IsInfisicalForwardRefusal reports whether an error code from the reserved name is the proxy's own answer rather than
// Infisical's answer passed on, so the CLI doesn't put it on Infisical.
func IsInfisicalForwardRefusal(code string) bool {
	return code == errorCodeBusy || code == errorCodeInfisicalUnreachable
}

// IsSessionRefusal reports whether an error code is the proxy refusing the session itself, which only a new session fixes.
func IsSessionRefusal(code string) bool {
	return code == errorCodeSessionInvalid
}

// A process runs one proxy, and starting agents is bursty, so a fixed number of requests to Infisical at once keeps a
// burst from holding open a connection per agent. The rest wait their turn rather than fail.
var reservedForwardSlots = make(chan struct{}, 8)

type reservedRoute struct {
	// Under config.INFISICAL_URL, which ends in /api.
	infisicalPath string
	decision      string
	forwardQuery  bool
}

// The only requests the reserved name answers. Through it, an agent reaches these session endpoints of the proxy's own
// Infisical and nothing else: an agent prompted to send data elsewhere can't use it as a way out.
func reservedRouteFor(path string) (reservedRoute, bool) {
	switch path {
	case "", "/", "/services", "/services/", "/api/v1/agent-vault/session/services":
		return reservedRoute{infisicalPath: "/v1/agent-vault/session/services", decision: decisionDiscovery}, true
	case "/api/v1/agent-vault/session/skills":
		return reservedRoute{infisicalPath: "/v1/agent-vault/session/skills", decision: decisionInfisical, forwardQuery: true}, true
	}
	return reservedRoute{}, false
}

// serveReservedName answers a request for the reserved name on the session the tunnel carries. The session is checked
// here rather than at the door, so a refused session's reason arrives as JSON, inside TLS for https.
func (ps *proxyServer) serveReservedName(w http.ResponseWriter, r *http.Request, t tunnel) {
	_, grant, err := ps.cache.lookup(t.sessionToken, nil)
	if err != nil {
		refusal := classifyGateRefusal(err)
		refusal.event.Str("host", DiscoveryHost).Str("sessionKey", sessionKey(t.sessionToken)).Str("decision", refusal.decision).
			Int("status", refusal.status).Msg(refusal.msg)
		writeProxyError(w, refusal.status, refusal.decision, refusal.code, refusal.body)
		return
	}

	status, decision := ps.forwardReservedRequest(w, r, t.sessionToken)

	method, path := truncateLogged(r.Method, maxLoggedMethodLen), truncatePath(requestPath(r))
	log.Info().Str("method", method).Str("host", DiscoveryHost).Str("path", path).Str("decision", decision).
		Int("status", status).Msg("agent-vault: request")
	ps.sessionLogs.record(grant, sessionLogRecord{
		Method:   method,
		Host:     DiscoveryHost,
		Port:     t.port,
		Path:     path,
		Status:   status,
		Decision: decision,
	})
}

func (ps *proxyServer) forwardReservedRequest(w http.ResponseWriter, r *http.Request, sessionToken string) (int, string) {
	route, ok := reservedRouteFor(r.URL.Path)
	if !ok {
		writeProxyError(w, http.StatusNotFound, decisionBlocked, errorCodeNotFound, "Agent Vault lists your services at "+DiscoveryURL)
		return http.StatusNotFound, decisionBlocked
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProxyError(w, http.StatusMethodNotAllowed, decisionBlocked, errorCodeMethodNotAllowed, "this address only answers GET")
		return http.StatusMethodNotAllowed, decisionBlocked
	}

	ctx, cancel := context.WithTimeout(r.Context(), reservedForwardTimeout)
	defer cancel()
	select {
	case reservedForwardSlots <- struct{}{}:
		defer func() { <-reservedForwardSlots }()
	case <-ctx.Done():
		if r.Context().Err() == nil {
			writeProxyError(w, http.StatusServiceUnavailable, decisionError, errorCodeBusy,
				"too many agents are starting through the proxy at once. Try again in a moment")
		}
		return http.StatusServiceUnavailable, decisionError
	}

	resp, err := ps.callInfisical(ctx, r.Method, route, r.URL.RawQuery, sessionToken)
	if err != nil {
		log.Warn().Err(err).Str("sessionKey", sessionKey(sessionToken)).Str("path", route.infisicalPath).
			Msg("agent-vault: could not reach Infisical for the reserved name")
		writeProxyError(w, http.StatusBadGateway, decisionError, errorCodeInfisicalUnreachable,
			"the proxy could not reach Infisical")
		return http.StatusBadGateway, decisionError
	}
	defer resp.RawBody().Close()

	w.Header().Set(HeaderDecision, route.decision)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(resp.StatusCode())
	if r.Method == http.MethodGet {
		if _, err := io.Copy(w, io.LimitReader(resp.RawBody(), reservedForwardMaxBytes)); err != nil && !errors.Is(err, context.Canceled) {
			log.Warn().Err(err).Str("sessionKey", sessionKey(sessionToken)).Msg("agent-vault: passing on Infisical's answer failed part way")
		}
	}
	return resp.StatusCode(), route.decision
}

// The session's own token is the only credential sent, whatever the agent put in its Authorization header, so an agent
// handed someone else's token can't use the reserved name to act as that session.
func (ps *proxyServer) callInfisical(ctx context.Context, method string, route reservedRoute, rawQuery, sessionToken string) (*resty.Response, error) {
	client, err := util.GetRestyClientWithPolicy(util.RetryPolicy{})
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
