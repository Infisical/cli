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
)

// newRecordingProxy is like newTestProxy but attaches a buffer-backed activity logger and a resolved agent
// identity, so tests can assert on the emitted records. recordActivity runs before any response byte is
// written, so reading buf after the client has the full response is safe.
func newRecordingProxy(t *testing.T, unmatchedHost, jwt string, scope agentScope, services []*resolvedService) (net.Conn, *bytes.Buffer) {
	t.Helper()
	cache := newAgentCache(func() string { return "" })
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{
		jwt:       jwt,
		scope:     scope,
		agentID:   "agent-id-1",
		agentName: "claude-agent",
		services:  services,
		lastSeen:  time.Now(),
	}
	buf := &bytes.Buffer{}
	ps := &proxyServer{
		opts:        Options{UnmatchedHost: unmatchedHost},
		cache:       cache,
		transport:   &http.Transport{},
		activityLog: &activityLogger{enabled: true, format: formatJSON, filter: filterAll, w: buf},
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
	return client, buf
}

func lastRecord(t *testing.T, buf *bytes.Buffer) ecsProbe {
	t.Helper()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	last := lines[len(lines)-1]
	if last == "" {
		t.Fatalf("no activity record was emitted")
	}
	var r ecsProbe
	if err := json.Unmarshal([]byte(last), &r); err != nil {
		t.Fatalf("record is not valid JSON: %q: %v", last, err)
	}
	return r
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
	// The identity must be captured in the outcome at forward time. If it were re-read from the cache after the
	// round trip, an eviction in between (revoked/expired token, or inactivity) would silently drop the record.
	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	cache := newAgentCache(func() string { return "" })
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{
		jwt: jwt, scope: scope, agentID: "id-9", agentName: "agent-9", lastSeen: time.Now(),
	}
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow},
		cache:     cache,
		transport: reflectingTransport{header: make(http.Header)},
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	_, outcome, err := ps.forward(req, "http", "example.com", "80", jwt, scope)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	// Simulate the entry being evicted during a slow round trip; the record must still have the identity.
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
	client, buf := newRecordingProxy(t, UnmatchedAllow, jwt, scope, services)

	doPlainRequest(t, client, "GET", "/hello", u.Host, jwt)

	rec := lastRecord(t, buf)
	if rec.Infisical.Decision != decisionBrokered || rec.HTTP.Response.StatusCode != 200 {
		t.Fatalf("want brokered/200, got %s/%d", rec.Infisical.Decision, rec.HTTP.Response.StatusCode)
	}
	if rec.Infisical.Service == nil || rec.Infisical.Service.Name != "internal" || rec.User == nil || rec.User.ID != "agent-id-1" {
		t.Fatalf("unexpected identity/service: %+v", rec)
	}
	if len(rec.Infisical.Credentials) != 1 || rec.Infisical.Credentials[0].Key != "API_KEY" {
		t.Fatalf("credentials not recorded: %+v", rec.Infisical.Credentials)
	}
	if rec.URL.Path != "/hello" {
		t.Fatalf("unexpected path: %q", rec.URL.Path)
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
	client, buf := newRecordingProxy(t, UnmatchedAllow, jwt, scope, nil) // no services => unmatched

	doPlainRequest(t, client, "GET", "/", u.Host, jwt)

	rec := lastRecord(t, buf)
	if rec.Infisical.Decision != decisionPassthrough || rec.HTTP.Response.StatusCode != 204 {
		t.Fatalf("want passthrough/204, got %s/%d", rec.Infisical.Decision, rec.HTTP.Response.StatusCode)
	}
	if rec.Infisical.Service != nil {
		t.Fatalf("passthrough should have null service: %+v", rec)
	}
}

func TestActivityRecordBlocked(t *testing.T) {
	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	client, buf := newRecordingProxy(t, UnmatchedBlock, jwt, scope, nil)

	resp := doPlainRequest(t, client, "GET", "/", "example.com", jwt)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 response, got %d", resp.StatusCode)
	}
	rec := lastRecord(t, buf)
	if rec.Infisical.Decision != decisionBlocked || rec.HTTP.Response.StatusCode != 403 {
		t.Fatalf("want blocked/403, got %s/%d", rec.Infisical.Decision, rec.HTTP.Response.StatusCode)
	}
}

func TestActivityRecordError(t *testing.T) {
	jwt := "a.b.c"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	// Point at a host that resolves nowhere useful so the upstream round-trip fails.
	services := []*resolvedService{{
		id:           "svc-err",
		name:         "unreachable",
		hostPatterns: parseHostPatterns("127.0.0.1"),
		isEnabled:    true,
	}}
	client, buf := newRecordingProxy(t, UnmatchedAllow, jwt, scope, services)

	// 127.0.0.1:1 is a closed port; the round-trip fails => error/502.
	resp := doPlainRequest(t, client, "GET", "/", "127.0.0.1:1", jwt)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("want 502 response, got %d", resp.StatusCode)
	}
	rec := lastRecord(t, buf)
	if rec.Infisical.Decision != decisionError || rec.HTTP.Response.StatusCode != 502 {
		t.Fatalf("want error/502, got %s/%d", rec.Infisical.Decision, rec.HTTP.Response.StatusCode)
	}
}
