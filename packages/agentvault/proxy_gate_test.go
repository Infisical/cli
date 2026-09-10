package agentvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
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
		{"revoked or expired session", &api.APIError{StatusCode: 401}, 403, "warn", decisionBlocked},
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
