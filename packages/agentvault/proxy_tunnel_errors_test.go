package agentvault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"github.com/Infisical/infisical-merge/packages/api"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type expiringResolver struct{ ttl time.Duration }

func (r expiringResolver) resolve(string) (*resolveResult, error) {
	exp := time.Now().Add(r.ttl)
	return &resolveResult{SessionID: "s1", ExpiresAt: &exp}, nil
}

// A client that tunnels through the proxy and trusts its CA, so requests exercise the in-tunnel path.
func newTunnellingClient(t *testing.T, rs sessionResolver) *http.Client {
	t.Helper()
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{transport: newUpstreamTransport(), ca: newCaManager(key, cert)}
	ps.setConfig(ProxyConfig{UnmatchedHost: UnmatchedAllow})
	ps.cache = newSessionCache(rs, ps.pollInterval)
	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	u, _ := url.Parse(front.URL)
	u.User = url.UserPassword(ProxyAuthUsername, "agv_tok")
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func get(t *testing.T, c *http.Client, target string) (int, string) {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func TestASessionLostInsideTheTunnelIsA403WithTheGateText(t *testing.T) {
	c := newTunnellingClient(t, expiringResolver{ttl: 200 * time.Millisecond})

	// The first request opens the tunnel while the session is valid; the upstream refusing is beside the point.
	get(t, c, "https://127.0.0.1:1/v1/thing")
	time.Sleep(300 * time.Millisecond)

	status, body := get(t, c, "https://127.0.0.1:1/v1/thing")
	if status != http.StatusForbidden {
		t.Fatalf("a dead session inside the tunnel got %d, which SDKs retry; want 403", status)
	}
	if body != "the session is no longer valid" {
		t.Fatalf("body %q differs from what the CONNECT gate says", body)
	}
}

func TestAnUpstreamFailureInsideTheTunnelKeepsTheDetailOutOfTheBody(t *testing.T) {
	var logs bytes.Buffer
	restore := log.Logger
	log.Logger = zerolog.New(&logs)
	defer func() { log.Logger = restore }()

	c := newTunnellingClient(t, sessionOnlyResolver{})
	status, body := get(t, c, "https://127.0.0.1:1/v1/thing")
	if status != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", status)
	}
	if strings.Contains(body, "dial tcp") || strings.Contains(body, "127.0.0.1:1") {
		t.Fatalf("the raw dial error reached the agent: %q", body)
	}
	if !strings.Contains(logs.String(), "connection refused") {
		t.Fatalf("the dial error was dropped instead of logged: %s", logs.String())
	}
}

type rejectedProxyResolver struct{}

func (rejectedProxyResolver) resolve(string) (*resolveResult, error) {
	return nil, &api.APIError{StatusCode: 401, Name: proxyTokenRejectedName, ErrorMessage: "Agent Vault proxy token has been revoked"}
}

func TestARevokedProxyTellsTheAgentTheProxyIsRevokedNotTheSession(t *testing.T) {
	c := newTunnellingClient(t, rejectedProxyResolver{})
	resp, err := c.Get("https://127.0.0.1:1/v1/thing")
	if err == nil {
		defer resp.Body.Close()
	}
	// The CONNECT gate refuses before any tunnel exists, so the client surfaces the proxy's status text.
	if err == nil || !strings.Contains(err.Error(), http.StatusText(http.StatusServiceUnavailable)) {
		t.Fatalf("expected the CONNECT to be refused with 503, got resp=%v err=%v", resp, err)
	}
}
