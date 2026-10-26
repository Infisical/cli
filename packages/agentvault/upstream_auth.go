package agentvault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	credentialSourceOAuth            = "oauth"
	oauthStatusConnected             = "connected"
	oauthStatusNeedsReauthorization  = "needs-reauthorization"
	oauthStatusNeedsAdditionalScopes = "needs-additional-scopes"

	// The backend's limits on requiredScopes; anything past them would fail the whole report.
	maxReportedScopes   = 50
	maxReportedScopeLen = 256
)

// The bodies of the 502 that replaces the upstream's auth failure. No WWW-Authenticate goes with it: passing
// the upstream's challenge on would start the agent's MCP client on an OAuth flow of its own, when the
// credential belongs to Infisical.
func upstreamAuthBody(code, message string) string {
	body, _ := json.Marshal(map[string]string{"error": code, "message": message})
	return string(body)
}

// For a credential the user stored, which only they can replace.
func staticCredentialRejectedBody(serviceName string) string {
	return upstreamAuthBody("upstream_auth_failed", fmt.Sprintf("The %s service's credential was rejected. Update it in Infisical Agent Vault.", serviceName))
}

func reauthorizationNeededBody(serviceName string) string {
	return upstreamAuthBody("upstream_auth_failed", fmt.Sprintf("The %s service needs to be reauthorized in Infisical Agent Vault.", serviceName))
}

// For a failure that may pass on its own: Infisical or the provider unreachable, a body that could not be
// replayed, or a refreshed token rejected for a reason Infisical does not know about.
func credentialUnavailableBody(serviceName string) string {
	return upstreamAuthBody("upstream_auth_unavailable", fmt.Sprintf("Couldn't get a valid credential for the %s service. Try again in a moment.", serviceName))
}

// Only a status Infisical reports, or an insufficient_scope challenge, means the user has to reauthorize.
func refreshFailedBody(serviceName, status string) string {
	if status == oauthStatusNeedsReauthorization || status == oauthStatusNeedsAdditionalScopes {
		return reauthorizationNeededBody(serviceName)
	}
	return credentialUnavailableBody(serviceName)
}

// The request body as it will go upstream, when it can be sent a second time. Only a body already held in
// memory, or none at all, can be: a streamed one is consumed by the first attempt.
func replayableBody(req *http.Request) ([]byte, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, true
	}
	if buffered, ok := req.Body.(*bufferedBody); ok {
		return buffered.data, true
	}
	return nil, false
}

// handleUpstreamAuth runs only for a refreshable credential the proxy injected, so every other credential
// sees the upstream's response untouched.
func (ps *proxyServer) handleUpstreamAuth(req *http.Request, resp *http.Response, svc *resolvedService, sessionToken string, sent *credential, body []byte, replayable bool) (*http.Response, error) {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		// An auth-error body can stay open indefinitely; draining it would stall the refresh.
		_ = resp.Body.Close()
		fresh, status, err := ps.cache.refreshCredential(sessionToken, svc.id, svc.hostPattern, sent)
		if err != nil {
			log.Warn().Err(err).Str("service", svc.name).Str("serviceId", svc.id).
				Msg("agent-vault: the upstream rejected the OAuth token and Infisical could not refresh it")
			return upstreamAuthFailed(req, credentialUnavailableBody(svc.name)), nil
		}
		if !replayable || bytes.Equal(fresh.value, sent.value) {
			log.Warn().Str("service", svc.name).Str("serviceId", svc.id).Bool("replayable", replayable).Str("status", status).
				Msg("agent-vault: the upstream rejected the OAuth token, not retrying")
			return upstreamAuthFailed(req, refreshFailedBody(svc.name, status)), nil
		}

		retry := req.Clone(req.Context())
		if len(body) == 0 {
			retry.Body = http.NoBody
		} else {
			retry.Body = &bufferedBody{Reader: bytes.NewReader(body), data: body}
		}
		injectCredential(retry, &fresh)
		retryResp, err := ps.transport.RoundTrip(retry)
		if err != nil {
			return nil, err
		}
		// Only a 401 or an insufficient_scope challenge is about the token. Any other 403 is the upstream's
		// answer to the request, which the refreshed token may only now have reached.
		if retryResp.StatusCode != http.StatusUnauthorized {
			if !ps.reportInsufficientScope(retryResp, sessionToken, svc, &fresh) {
				return retryResp, nil
			}
			status = oauthStatusNeedsAdditionalScopes
		}
		_ = retryResp.Body.Close()
		log.Warn().Str("service", svc.name).Str("serviceId", svc.id).Int("retryStatus", retryResp.StatusCode).
			Msg("agent-vault: the upstream rejected the refreshed OAuth token too")
		return upstreamAuthFailed(req, refreshFailedBody(svc.name, status)), nil

	case http.StatusForbidden:
		if !ps.reportInsufficientScope(resp, sessionToken, svc, sent) {
			return resp, nil
		}
		_ = resp.Body.Close()
		log.Warn().Str("service", svc.name).Str("serviceId", svc.id).
			Msg("agent-vault: the upstream needs OAuth scopes this service was not granted")
		return upstreamAuthFailed(req, reauthorizationNeededBody(svc.name)), nil
	}
	return resp, nil
}

// Reports whether the response was an insufficient_scope challenge. The scopes go to Infisical so the
// service shows what reauthorizing has to request; a challenge naming none has nothing to record.
func (ps *proxyServer) reportInsufficientScope(resp *http.Response, sessionToken string, svc *resolvedService, sent *credential) bool {
	if resp.StatusCode != http.StatusForbidden {
		return false
	}
	params := bearerChallengeParams(resp.Header.Values("WWW-Authenticate"))
	if params["error"] != "insufficient_scope" {
		return false
	}
	scopes := challengedScopes(params["scope"])
	if len(scopes) == 0 {
		return true
	}
	// In the background: the agent's answer does not depend on the report, so it need not wait for Infisical.
	go func() {
		if err := ps.cache.reportMissingScopes(sessionToken, svc.id, svc.hostPattern, sent, scopes); err != nil {
			log.Warn().Err(err).Str("service", svc.name).Str("serviceId", svc.id).
				Msg("agent-vault: could not report the upstream's required scopes to Infisical")
		}
	}()
	return true
}

func challengedScopes(raw string) []string {
	var scopes []string
	for _, scope := range strings.Fields(raw) {
		if len(scope) > maxReportedScopeLen {
			continue
		}
		scopes = append(scopes, scope)
		if len(scopes) == maxReportedScopes {
			break
		}
	}
	return scopes
}

func upstreamAuthFailed(req *http.Request, body string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		Status:        "502 Bad Gateway",
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// The auth-params of the Bearer challenges in WWW-Authenticate (RFC 9110 section 11.6.1), names
// lower-cased, first occurrence kept. Params of other schemes are skipped.
func bearerChallengeParams(values []string) map[string]string {
	params := map[string]string{}
	for _, value := range values {
		inBearer := false
		i := 0
		for i < len(value) {
			for i < len(value) && (value[i] == ' ' || value[i] == '\t' || value[i] == ',') {
				i++
			}
			start := i
			for i < len(value) && isTokenChar(value[i]) {
				i++
			}
			if i == start {
				i++
				continue
			}
			name := value[start:i]
			j := i
			for j < len(value) && (value[j] == ' ' || value[j] == '\t') {
				j++
			}
			if j >= len(value) || value[j] != '=' {
				inBearer = strings.EqualFold(name, "bearer")
				continue
			}
			i = j + 1
			for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
				i++
			}
			var paramValue string
			if i < len(value) && value[i] == '"' {
				var b strings.Builder
				i++
				for i < len(value) && value[i] != '"' {
					if value[i] == '\\' && i+1 < len(value) {
						i++
					}
					b.WriteByte(value[i])
					i++
				}
				i++
				paramValue = b.String()
			} else {
				start := i
				for i < len(value) && isTokenChar(value[i]) {
					i++
				}
				paramValue = value[start:i]
			}
			key := strings.ToLower(name)
			if _, seen := params[key]; inBearer && !seen {
				params[key] = paramValue
			}
		}
	}
	return params
}

func isTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}
