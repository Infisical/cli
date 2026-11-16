package agentvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// A request turned away before the tunnel used to answer the agent and write nothing, so an operator
// watching the proxy saw a failing agent and no reason for it.
func TestGateDenialsAreLogged(t *testing.T) {
	const token = "agv_a_real_looking_session_token"

	for _, tc := range []struct {
		name     string
		err      error
		status   int
		level    string
		decision string
	}{
		{"revoked or expired session", &api.APIError{StatusCode: 401, Name: infisicalUnauthorizedName}, 403, "warn", decisionBlocked},
		{"infisical unreachable", errors.New("dial tcp: connection refused"), 502, "error", decisionError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			restore := log.Logger
			log.Logger = zerolog.New(&buf)
			defer func() { log.Logger = restore }()

			rec := httptest.NewRecorder()
			(&proxyServer{}).denyAtGate(rec, token, "api.example.com", "443", tc.err)

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}

			var line map[string]any
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("no log line: %v (%q)", err, buf.String())
			}
			if line["level"] != tc.level {
				t.Errorf("level = %v, want %s", line["level"], tc.level)
			}
			if line["decision"] != tc.decision {
				t.Errorf("decision = %v, want %s", line["decision"], tc.decision)
			}
			if line["host"] != "api.example.com:443" {
				t.Errorf("host = %v", line["host"])
			}
			// The correlator is the hash the cache is keyed on, never the token itself.
			if line["sessionKey"] != sessionKey(token) {
				t.Errorf("sessionKey = %v", line["sessionKey"])
			}
			if bytes.Contains(buf.Bytes(), []byte(token)) {
				t.Error("the session token must never reach the log")
			}
		})
	}
}

func TestTheHTTPDoorAtTheFreeLimitPassesOnTheServersMessageAndLogsItOnceAMinute(t *testing.T) {
	logs := captureLogs(t)
	const serverMessage = "This organization used its 5,000 free Agent Vault requests this month. They reset on December 1."
	resolver := &stubResolver{err: &api.APIError{StatusCode: 400, Name: freeLimitReachedName, ErrorMessage: serverMessage}}
	ps := &proxyServer{transport: newUpstreamTransport()}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(resolver, ps.pollInterval)

	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)
	proxyURL, _ := url.Parse(front.URL)
	proxyURL.User = url.UserPassword(ProxyAuthUsername, "agv_tok")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	for i := 0; i < 3; i++ {
		resp, err := client.Get("http://api.example.com/v1/things")
		if err != nil {
			t.Fatal(err)
		}
		var body proxyErrorBody
		decodeErr := json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get(HeaderError) != errorCodeFreeLimitReached {
			t.Fatalf("got %d %s=%q, want 403 %s", resp.StatusCode, HeaderError, resp.Header.Get(HeaderError), errorCodeFreeLimitReached)
		}
		if body.Error != errorCodeFreeLimitReached || body.Message != serverMessage || body.Hint != proxyErrorHints[errorCodeFreeLimitReached] {
			t.Fatalf("body = %+v, want the code, the server's message and the hint", body)
		}
	}

	out := logs.String()
	const refusedLine = "this organization used its free Agent Vault requests for this month"
	if n := strings.Count(out, `"level":"warn"`); n != 1 {
		t.Fatalf("got %d warn lines for 3 refusals in a minute, want 1: %s", n, out)
	}
	if n := strings.Count(out, refusedLine); n != 3 {
		t.Fatalf("got %d refusal lines, want each one at warn or debug: %s", n, out)
	}
}
