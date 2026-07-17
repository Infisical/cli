package agentproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type activityLine struct {
	Level       string              `json:"level"`
	Event       string              `json:"event"`
	Decision    string              `json:"decision"`
	AgentID     string              `json:"agentId"`
	AgentName   string              `json:"agentName"`
	ServiceName string              `json:"serviceName"`
	Host        string              `json:"host"`
	Path        string              `json:"path"`
	Status      int                 `json:"status"`
	Credentials []AppliedCredential `json:"credentials"`
}

func captureLogs(t *testing.T, level zerolog.Level) *bytes.Buffer {
	t.Helper()
	prevLogger := log.Logger
	prevGlobal := zerolog.GlobalLevel()
	buf := &bytes.Buffer{}
	log.Logger = zerolog.New(zerolog.SyncWriter(buf)).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(level)
	t.Cleanup(func() {
		log.Logger = prevLogger
		zerolog.SetGlobalLevel(prevGlobal)
	})
	return buf
}

func lastActivity(t *testing.T, buf *bytes.Buffer) activityLine {
	t.Helper()
	var last *activityLine
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var l activityLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		if l.Event != activityEventName {
			continue
		}
		cp := l
		last = &cp
	}
	if last == nil {
		t.Fatalf("no activity log line emitted; buffer:\n%s", buf.String())
	}
	return *last
}

func newRecordingProxy(t *testing.T, unmatchedHost, jwt string, scope agentScope, services []*resolvedService) net.Conn {
	t.Helper()
	cache := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{
		jwt: jwt, scope: scope, agentID: "agent-id-1", agentName: "claude-agent", services: services, lastSeen: time.Now(),
	}
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: unmatchedHost},
		cache:     cache,
		leases:    newLeaseStore(func() string { return "" }),
		transport: &http.Transport{},
	}
	client, server := net.Pipe()
	l := newOneShotListener(server)
	srv := ps.newFrontServer()
	srv.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed || s == http.StateHijacked {
			_ = l.Close()
		}
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func doPlainRequest(t *testing.T, client net.Conn, method, target, hostPort, jwt string) *http.Response {
	t.Helper()
	fmt.Fprintf(client, "%s http://%s%s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nConnection: close\r\n\r\n",
		method, hostPort, target, hostPort, proxyAuthHeader("proj", "prod", "/", jwt))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

func TestForwardCapturesIdentityForRecord(t *testing.T) {
	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	cache := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{
		jwt: jwt, scope: scope, agentID: "id-9", agentName: "agent-9", lastSeen: time.Now(),
	}
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow},
		cache:     cache,
		leases:    newLeaseStore(func() string { return "" }),
		transport: reflectingTransport{header: make(http.Header)},
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	_, outcome, err := ps.forward(req, "http", "example.com", "80", jwt, scope)
	if err != nil {
		t.Fatal(err)
	}
	delete(cache.entries, cacheKey(jwt, scope))
	if !outcome.identityResolved || outcome.agentID != "id-9" || outcome.agentName != "agent-9" {
		t.Fatalf("identity not captured in outcome: %+v", outcome)
	}
}

func TestActivityRecordBrokered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		id:           "svc-1",
		name:         "internal",
		hostPatterns: parseHostPatterns(u.Hostname()),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{secretKey: "API_KEY", role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}
	buf := captureLogs(t, zerolog.DebugLevel)
	client := newRecordingProxy(t, UnmatchedAllow, jwt, scope, services)

	doPlainRequest(t, client, "GET", "/hello", u.Host, jwt)

	rec := lastActivity(t, buf)
	if rec.Level != "info" || rec.Decision != decisionBrokered || rec.Status != 200 {
		t.Fatalf("want info/brokered/200, got %s/%s/%d", rec.Level, rec.Decision, rec.Status)
	}
	if rec.ServiceName != "internal" || rec.AgentID != "agent-id-1" {
		t.Fatalf("unexpected identity/service: %+v", rec)
	}
	if len(rec.Credentials) != 1 || rec.Credentials[0].Key != "API_KEY" {
		t.Fatalf("credentials not recorded: %+v", rec.Credentials)
	}
	if rec.Path != "/hello" {
		t.Fatalf("unexpected path: %q", rec.Path)
	}
}

func TestActivityRecordPassthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	buf := captureLogs(t, zerolog.DebugLevel) // passthrough is debug
	client := newRecordingProxy(t, UnmatchedAllow, jwt, scope, nil)

	doPlainRequest(t, client, "GET", "/", u.Host, jwt)

	rec := lastActivity(t, buf)
	if rec.Level != "debug" || rec.Decision != decisionPassthrough || rec.Status != 204 {
		t.Fatalf("want debug/passthrough/204, got %s/%s/%d", rec.Level, rec.Decision, rec.Status)
	}
	if rec.ServiceName != "" {
		t.Fatalf("passthrough should have no service: %+v", rec)
	}
}

func TestActivityRecordBlocked(t *testing.T) {
	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	buf := captureLogs(t, zerolog.DebugLevel)
	client := newRecordingProxy(t, UnmatchedBlock, jwt, scope, nil)

	resp := doPlainRequest(t, client, "GET", "/", "example.com", jwt)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 response, got %d", resp.StatusCode)
	}
	rec := lastActivity(t, buf)
	if rec.Level != "warn" || rec.Decision != decisionBlocked || rec.Status != 403 {
		t.Fatalf("want warn/blocked/403, got %s/%s/%d", rec.Level, rec.Decision, rec.Status)
	}
}

func TestActivityRecordError(t *testing.T) {
	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		id:           "svc-err",
		name:         "unreachable",
		hostPatterns: parseHostPatterns("127.0.0.1"),
		isEnabled:    true,
	}}
	buf := captureLogs(t, zerolog.DebugLevel)
	client := newRecordingProxy(t, UnmatchedAllow, jwt, scope, services)

	resp := doPlainRequest(t, client, "GET", "/", "127.0.0.1:1", jwt)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("want 502 response, got %d", resp.StatusCode)
	}
	rec := lastActivity(t, buf)
	if rec.Level != "error" || rec.Decision != decisionError || rec.Status != 502 {
		t.Fatalf("want error/error/502, got %s/%s/%d", rec.Level, rec.Decision, rec.Status)
	}
}

func TestActivityRecordPathTruncated(t *testing.T) {
	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	buf := captureLogs(t, zerolog.DebugLevel)
	client := newRecordingProxy(t, UnmatchedAllow, jwt, scope, nil)

	longPath := "/" + strings.Repeat("a", maxLoggedPathLen+500)
	doPlainRequest(t, client, "GET", longPath, "127.0.0.1:1", jwt)

	rec := lastActivity(t, buf)
	if len(rec.Path) > maxLoggedPathLen+len("...[truncated]") {
		t.Fatalf("path not capped: len=%d", len(rec.Path))
	}
	if !strings.HasSuffix(rec.Path, "...[truncated]") {
		t.Fatalf("expected truncation marker, got %q", rec.Path)
	}
}

func TestActivityRespectsLogLevel(t *testing.T) {
	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	buf := captureLogs(t, zerolog.WarnLevel)
	client := newRecordingProxy(t, UnmatchedBlock, jwt, scope, nil)

	doPlainRequest(t, client, "GET", "/", "example.com", jwt) // blocked -> warn
	rec := lastActivity(t, buf)
	if rec.Decision != decisionBlocked {
		t.Fatalf("want blocked at warn level, got %s", rec.Decision)
	}
	if strings.Contains(buf.String(), `"decision":"brokered"`) {
		t.Fatalf("brokered (info) should be suppressed at warn level")
	}
}

func TestEmitActivityLogsDynamicSecret(t *testing.T) {
	buf := captureLogs(t, zerolog.DebugLevel)
	ps := &proxyServer{}
	name := "db-api"
	svcID := "svc-9"
	outcome := forwardOutcome{
		identityResolved: true,
		agentID:          "agent-1",
		service:          &resolvedService{id: svcID, name: name},
		applied: []AppliedCredential{
			{DynamicSecretName: "my-postgres-creds", DynamicSecretField: "DB_PASSWORD", Role: roleHeaderRewrite, Header: "Authorization"},
		},
	}
	ps.emitActivity("GET", "/query", "db.internal", "443", decisionBrokered,
		200, agentScope{projectID: "proj", environment: "prod", secretPath: "/"}, outcome, nil)

	rec := lastActivity(t, buf)
	if len(rec.Credentials) != 1 {
		t.Fatalf("want 1 credential, got %+v", rec.Credentials)
	}
	c := rec.Credentials[0]
	if c.DynamicSecretName != "my-postgres-creds" || c.DynamicSecretField != "DB_PASSWORD" || c.Key != "" {
		t.Fatalf("dynamic secret not logged correctly: %+v", c)
	}
}

func TestEmitActivityLogsResolutionError(t *testing.T) {
	buf := captureLogs(t, zerolog.DebugLevel)
	ps := &proxyServer{}
	ps.emitActivity("GET", "/x", "example.com", "443", decisionError, 502,
		agentScope{projectID: "proj", environment: "prod", secretPath: "/"},
		forwardOutcome{identityResolved: false}, fmt.Errorf("failed to resolve agent permissions"))
	rec := lastActivity(t, buf)
	if rec.Level != "error" || rec.Decision != decisionError {
		t.Fatalf("want error/error, got %s/%s", rec.Level, rec.Decision)
	}
	if rec.AgentID != "" {
		t.Fatalf("resolution error should have empty agentId, got %q", rec.AgentID)
	}
}
