package agentproxy

import (
	"bufio"
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
)

func proxyAuthHeader(projectID, environment, secretPath, jwt string) string {
	password := fmt.Sprintf("%s/%s:%s", environment, strings.TrimPrefix(secretPath, "/"), jwt)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(projectID+":"+password))
}

// newTestProxy returns a proxyServer whose cache is pre-populated for jwt+scope, so no
// Infisical calls happen, plus the client side of a pipe with handleConn running on the other end.
func newTestProxy(t *testing.T, unmatchedHost, jwt string, scope agentScope, services []*resolvedService) net.Conn {
	t.Helper()
	cache := newAgentCache(func() string { return "" })
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{
		jwt:      jwt,
		scope:    scope,
		services: services,
		lastSeen: time.Now(),
	}
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: unmatchedHost},
		cache:     cache,
		transport: &http.Transport{},
	}
	client, server := net.Pipe()
	go ps.handleConn(server)
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

	// two sequential requests exercise plain-path keep-alive
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
	// A client that names the injected header in its Connection field must not be able to strip
	// the injected credential: "injected always wins". Hop-by-hop stripping runs before injection.
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

	// hostile request: Connection lists Authorization (would delete it if stripping ran after inject)
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
