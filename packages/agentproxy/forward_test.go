package agentproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
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

func proxyAuthHeader(projectID, environment, secretPath, jwt string) string {
	password := fmt.Sprintf("%s/%s:%s", environment, strings.TrimPrefix(secretPath, "/"), jwt)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(projectID+":"+password))
}

func newTestProxy(t *testing.T, unmatchedHost, jwt string, scope agentScope, services []*resolvedService) net.Conn {
	t.Helper()
	cache := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{
		jwt:      jwt,
		scope:    scope,
		services: services,
		lastSeen: time.Now(),
	}
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: unmatchedHost},
		resolver:  cache,
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

func TestPlainForwardInjectsCredentialsAndKeepsAlive(t *testing.T) {
	var gotAuth []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	hostname := u.Hostname()

	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		name:         "internal",
		hostPatterns: parseHostPatterns(hostname),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}
	client := newTestProxy(t, UnmatchedAllow, jwt, scope, services)
	reader := bufio.NewReader(client)

	for i := 0; i < 2; i++ {
		_, err := fmt.Fprintf(client, "GET http://%s/hello HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
			u.Host, u.Host, proxyAuthHeader("proj", "prod", "/", jwt))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: unexpected status %d", i, resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	if len(gotAuth) != 2 {
		t.Fatalf("expected 2 upstream requests, got %d", len(gotAuth))
	}
	for i, auth := range gotAuth {
		if auth != "Bearer real_secret" {
			t.Fatalf("request %d: credential not injected, Authorization = %q", i, auth)
		}
	}
}

func TestPlainForwardInjectedHeaderSurvivesHostileConnectionHeader(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		name:         "internal",
		hostPatterns: parseHostPatterns(u.Hostname()),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}
	client := newTestProxy(t, UnmatchedAllow, jwt, scope, services)

	fmt.Fprintf(client, "GET http://%s/hello HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nConnection: Authorization\r\nAuthorization: Bearer client_fake\r\n\r\n",
		u.Host, u.Host, proxyAuthHeader("proj", "prod", "/", jwt))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if gotAuth != "Bearer real_secret" {
		t.Fatalf("injected credential must survive a hostile Connection header; upstream saw Authorization = %q", gotAuth)
	}
}

func TestPlainForwardRejectsHTTPSAbsoluteForm(t *testing.T) {
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	client := newTestProxy(t, UnmatchedAllow, "jwt", scope, nil)

	fmt.Fprintf(client, "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: %s\r\n\r\n",
		proxyAuthHeader("proj", "prod", "/", "jwt"))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for https:// absolute-form (no TLS-strip), got %d", resp.StatusCode)
	}
}

func TestPlainForwardRequiresProxyAuth(t *testing.T) {
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	client := newTestProxy(t, UnmatchedAllow, "jwt", scope, nil)

	fmt.Fprintf(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407 without Proxy-Authorization, got %d", resp.StatusCode)
	}
}

func TestPlainForwardBlocksUnmatchedHost(t *testing.T) {
	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	client := newTestProxy(t, UnmatchedBlock, jwt, scope, nil)

	fmt.Fprintf(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: %s\r\n\r\n",
		proxyAuthHeader("proj", "prod", "/", jwt))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 in block mode for an unmatched host, got %d", resp.StatusCode)
	}
}

// An agent that hangs up mid-request (an interrupted prompt, or the agent exiting) must not put an
// error on the terminal its TUI is drawing to.
func TestClientAbortIsNotLoggedAsError(t *testing.T) {
	var buf bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = previous })

	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { close(release); upstream.Close() })

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "dev", secretPath: "/"}
	client := newTestProxy(t, UnmatchedAllow, jwt, scope, nil)

	if _, err := fmt.Fprintf(client, "POST http://%s/v1/messages HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nContent-Length: 0\r\n\r\n",
		u.Host, u.Host, proxyAuthHeader("proj", "dev", "/", jwt)); err != nil {
		t.Fatal(err)
	}
	// Give the proxy time to reach the (hanging) upstream, then go away like an interrupted agent.
	time.Sleep(200 * time.Millisecond)
	_ = client.Close()

	var line string
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if line = buf.String(); strings.Contains(line, activityEventName) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(line, activityEventName) {
		t.Fatalf("expected an activity record for the aborted request, got %q", line)
	}
	if !strings.Contains(line, `"decision":"`+decisionCanceled+`"`) {
		t.Errorf("expected decision %q, got %q", decisionCanceled, line)
	}
	if strings.Contains(line, `"level":"error"`) {
		t.Errorf("client abort logged at error level: %q", line)
	}
	if strings.Contains(line, `"status":`) {
		t.Errorf("a canceled request has no response status to report: %q", line)
	}
}

// A credential already applied to the request must stay on the record at its normal level, so hanging
// up mid-request cannot keep a brokered call out of the activity log.
func TestClientAbortStillRecordsBrokeredCredential(t *testing.T) {
	var buf bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = previous })

	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() { close(release); upstream.Close() })

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "dev", secretPath: "/"}
	services := []*resolvedService{{
		name:         "internal",
		hostPatterns: parseHostPatterns(u.Hostname()),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{secretKey: "GITHUB_PAT", role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}
	client := newTestProxy(t, UnmatchedAllow, jwt, scope, services)

	if _, err := fmt.Fprintf(client, "POST http://%s/issues HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nContent-Length: 0\r\n\r\n",
		u.Host, u.Host, proxyAuthHeader("proj", "dev", "/", jwt)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_ = client.Close()

	var line string
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if line = buf.String(); strings.Contains(line, activityEventName) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(line, `"decision":"`+decisionBrokered+`"`) {
		t.Errorf("a credential was applied, so the record must stay %q: %q", decisionBrokered, line)
	}
	if !strings.Contains(line, `"level":"info"`) {
		t.Errorf("brokered records must stay at info so they survive the default filter: %q", line)
	}
	if !strings.Contains(line, "GITHUB_PAT") {
		t.Errorf("the applied credential must still be named on the record: %q", line)
	}
	if strings.Contains(line, "real_secret") {
		t.Errorf("the record must never contain the secret value: %q", line)
	}
}
