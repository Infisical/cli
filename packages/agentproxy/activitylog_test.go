package agentproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeJWT builds an unsigned-payload JWT (header.payload.signature) whose payload is the given claims JSON.
// The proxy only base64url-decodes the payload; header and signature are opaque here.
func makeJWT(t *testing.T, payloadJSON string) string {
	t.Helper()
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return strings.Join([]string{seg(`{"alg":"HS256"}`), seg(payloadJSON), "sig"}, ".")
}

func TestDecodeAgentIdentity(t *testing.T) {
	cases := []struct {
		name     string
		jwt      string
		wantID   string
		wantName string
	}{
		{"valid", makeJWT(t, `{"identityId":"id-1","identityName":"claude-agent"}`), "id-1", "claude-agent"},
		{"missing name", makeJWT(t, `{"identityId":"id-2"}`), "id-2", ""},
		{"malformed (not three segments)", "not-a-jwt", "", ""},
		{"malformed payload", "a.$$$.c", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, name := decodeAgentIdentity(tc.jwt)
			if id != tc.wantID || name != tc.wantName {
				t.Fatalf("got (%q, %q), want (%q, %q)", id, name, tc.wantID, tc.wantName)
			}
		})
	}
}

func TestApplyCredentialsReportsHeaderRewrite(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{secretKey: "ACME_API_KEY", role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "sk_real"},
	}}
	applied, err := applyCredentials(req, svc)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 {
		t.Fatalf("want 1 applied credential, got %d", len(applied))
	}
	got := applied[0]
	if got.Key != "ACME_API_KEY" || got.Role != roleHeaderRewrite || got.Header != "Authorization" {
		t.Fatalf("unexpected applied credential: %+v", got)
	}
}

func TestApplyCredentialsReportsBasicAuthPair(t *testing.T) {
	req := newReq(t, "")
	svc := &resolvedService{credentials: []resolvedCredential{
		{secretKey: "JIRA_USER", role: roleHeaderRewrite, headerPurpose: purposeUsername, value: "user"},
		{secretKey: "JIRA_PASS", role: roleHeaderRewrite, headerPurpose: purposePassword, value: "pass"},
	}}
	applied, err := applyCredentials(req, svc)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 {
		t.Fatalf("want 2 applied credentials, got %d: %+v", len(applied), applied)
	}
	for _, c := range applied {
		if c.Header != "Authorization" || c.Role != roleHeaderRewrite {
			t.Fatalf("basic-auth entry should target Authorization: %+v", c)
		}
	}
	if applied[0].Purpose != purposeUsername || applied[1].Purpose != purposePassword {
		t.Fatalf("purposes not reported: %+v", applied)
	}
}

func TestApplyCredentialsReportsOnlyMatchedSurfaces(t *testing.T) {
	// Placeholder is present in the query only, though the service allows path+query.
	req := httptest.NewRequest("GET", "https://api.example.com/orders?id=placeholder_x", nil)
	svc := &resolvedService{credentials: []resolvedCredential{
		{secretKey: "ACME_ACCOUNT", role: roleCredentialSub, placeholder: "placeholder_x", value: "real", surfaces: []string{surfacePath, surfaceQuery}},
	}}
	applied, err := applyCredentials(req, svc)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 {
		t.Fatalf("want 1 applied credential, got %d", len(applied))
	}
	if len(applied[0].Surfaces) != 1 || applied[0].Surfaces[0] != surfaceQuery {
		t.Fatalf("want only [query], got %v", applied[0].Surfaces)
	}
}

func TestApplyCredentialsOmitsSubstitutionThatMatchedNothing(t *testing.T) {
	// Placeholder appears nowhere in the request, so the substitution injects nothing and is omitted.
	req := httptest.NewRequest("GET", "https://api.example.com/orders", nil)
	svc := &resolvedService{credentials: []resolvedCredential{
		{secretKey: "ACME_ACCOUNT", role: roleCredentialSub, placeholder: "placeholder_x", value: "real", surfaces: []string{surfacePath, surfaceQuery}},
	}}
	applied, err := applyCredentials(req, svc)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Fatalf("want 0 applied credentials, got %+v", applied)
	}
}

func newTestLogger(w *bytes.Buffer, filter string) *activityLogger {
	return &activityLogger{enabled: true, format: formatJSON, filter: filter, w: w}
}

// ecsProbe decodes the ECS-shaped json output so tests can assert on the emitted fields.
type ecsProbe struct {
	Timestamp string `json:"@timestamp"`
	Event     struct {
		Action  string `json:"action"`
		Outcome string `json:"outcome"`
	} `json:"event"`
	HTTP struct {
		Request struct {
			Method string `json:"method"`
		} `json:"request"`
		Response struct {
			StatusCode int `json:"status_code"`
		} `json:"response"`
	} `json:"http"`
	URL struct {
		Path string `json:"path"`
	} `json:"url"`
	Server struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
	} `json:"server"`
	User *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
	Infisical struct {
		SchemaVersion int    `json:"schema_version"`
		Decision      string `json:"decision"`
		Service       *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"service"`
		Credentials []AppliedCredential `json:"credentials"`
	} `json:"infisical"`
}

func decodeRecords(t *testing.T, buf *bytes.Buffer) []ecsProbe {
	t.Helper()
	var recs []ecsProbe
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var r ecsProbe
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line is not valid JSON: %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	return recs
}

func TestActivityLoggerFilters(t *testing.T) {
	all := []string{decisionBrokered, decisionPassthrough, decisionBlocked, decisionError}
	cases := []struct {
		filter string
		want   []string
	}{
		{filterAll, []string{decisionBrokered, decisionPassthrough, decisionBlocked, decisionError}},
		{filterBrokered, []string{decisionBrokered, decisionBlocked, decisionError}},
		{filterErrors, []string{decisionBlocked, decisionError}},
	}
	for _, tc := range cases {
		t.Run(tc.filter, func(t *testing.T) {
			var buf bytes.Buffer
			l := newTestLogger(&buf, tc.filter)
			for _, d := range all {
				l.Record(activityRecord{Decision: d})
			}
			recs := decodeRecords(t, &buf)
			var got []string
			for _, r := range recs {
				got = append(got, r.Infisical.Decision)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("filter %q: got %v, want %v", tc.filter, got, tc.want)
			}
		})
	}
}

func decodeFile(t *testing.T, path string) []ecsProbe {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var buf bytes.Buffer
	buf.Write(data)
	return decodeRecords(t, &buf)
}

func TestActivityLoggerReopenAfterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "activity.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	l := &activityLogger{enabled: true, format: formatJSON, filter: filterAll, sink: path, w: f, file: f}

	l.Record(activityRecord{Decision: decisionBrokered})

	// Simulate logrotate's rename+create: move the current file aside, then signal a reopen.
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := l.reopen(); err != nil {
		t.Fatalf("reopen: %v", err)
	}

	l.Record(activityRecord{Decision: decisionError})

	// The pre-rotation record stayed with the rotated file; the post-reopen record went to the fresh file.
	if old := decodeFile(t, rotated); len(old) != 1 || old[0].Infisical.Decision != decisionBrokered {
		t.Fatalf("rotated file should hold the pre-rotation record, got %+v", old)
	}
	if cur := decodeFile(t, path); len(cur) != 1 || cur[0].Infisical.Decision != decisionError {
		t.Fatalf("new file should hold only the post-reopen record, got %+v", cur)
	}
}

func TestActivityLoggerReopenStdoutIsNoop(t *testing.T) {
	var buf bytes.Buffer
	l := &activityLogger{enabled: true, format: formatJSON, filter: filterAll, sink: "stdout", w: &buf}
	if err := l.reopen(); err != nil {
		t.Fatalf("reopen on non-file sink should be a no-op, got %v", err)
	}
}

func TestPrettyLineIncludesScope(t *testing.T) {
	l := &activityLogger{enabled: true, format: formatPretty, filter: filterAll}
	name := "acme-api"
	line := l.prettyLine(activityRecord{
		Decision:    decisionBrokered,
		ProjectID:   "53c8b330-f5d4-40f2-be55-e7d1fb56674b",
		Environment: "dev",
		SecretPath:  "/agent-proxy-test",
		ServiceName: &name,
		Method:      "GET",
		Host:        "httpbingo.org",
		Path:        "/headers",
		Status:      200,
	})
	// Scope column shows truncated project, env, and path.
	for _, want := range []string{"53c8b330..", "dev", "/agent-proxy-test"} {
		if !strings.Contains(line, want) {
			t.Fatalf("pretty line missing %q: %q", want, line)
		}
	}
}

func TestPrettyLineStripsControlBytes(t *testing.T) {
	l := &activityLogger{enabled: true, format: formatPretty, filter: filterAll}
	// An agent-controlled path with a newline and an ANSI escape must not break the line or emit escapes.
	line := l.prettyLine(activityRecord{
		Decision: decisionBrokered,
		Method:   "GET",
		Host:     "evil.example.com",
		Path:     "/x\nbrokered forged\x1b[31m",
		Status:   200,
	})
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
		t.Fatalf("output must be exactly one line: %q", line)
	}
	if strings.ContainsRune(line, '\x1b') {
		t.Fatalf("terminal escape leaked into pretty output: %q", line)
	}
}

func TestActivityLoggerDisabledWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	l := &activityLogger{enabled: false, format: formatJSON, filter: filterAll, w: &buf}
	l.Record(activityRecord{Decision: decisionBrokered})
	if buf.Len() != 0 {
		t.Fatalf("disabled logger wrote output: %q", buf.String())
	}
}

func TestActivityLoggerNilSafe(t *testing.T) {
	var l *activityLogger
	l.Record(activityRecord{Decision: decisionBrokered}) // must not panic
}

func TestActivityRecordJSONShape(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf, filterAll)
	name := "acme-api"
	id := "svc-1"
	l.Record(activityRecord{
		Decision:    decisionBrokered,
		Method:      "POST",
		Host:        "api.acme.com",
		Port:        443,
		Path:        "/v1/accounts/placeholder_acme/orders",
		Status:      200,
		ServiceID:   &id,
		ServiceName: &name,
		Credentials: []AppliedCredential{
			{Key: "ACME_API_KEY", Role: roleHeaderRewrite, Header: "Authorization"},
			{Key: "ACME_ACCOUNT", Role: roleCredentialSub, Surfaces: []string{surfacePath, surfaceQuery}},
		},
	})
	recs := decodeRecords(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	// The path retains the placeholder and never a real secret.
	if !strings.Contains(r.URL.Path, "placeholder_acme") {
		t.Fatalf("path lost its placeholder: %q", r.URL.Path)
	}
	if r.Server.Port != 443 || r.HTTP.Response.StatusCode != 200 || r.Infisical.Service == nil || r.Infisical.Service.Name != "acme-api" {
		t.Fatalf("unexpected record: %+v", r)
	}
	if r.Event.Outcome != "success" {
		t.Fatalf("brokered should map to event.outcome=success, got %q", r.Event.Outcome)
	}
	if len(r.Infisical.Credentials) != 2 || r.Infisical.Credentials[1].Surfaces[1] != surfaceQuery {
		t.Fatalf("credentials not round-tripped: %+v", r.Infisical.Credentials)
	}
}

func TestCredShorthand(t *testing.T) {
	got := credShorthand([]AppliedCredential{
		{Key: "ACME_API_KEY", Role: roleHeaderRewrite, Header: "Authorization"},
		{Key: "ACME_ACCOUNT", Role: roleCredentialSub, Surfaces: []string{surfacePath, surfaceQuery}},
	})
	want := "header:ACME_API_KEY path,query:ACME_ACCOUNT"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
