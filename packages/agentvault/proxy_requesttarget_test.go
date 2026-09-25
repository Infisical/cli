package agentvault

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Literal bytes on the wire, because a Go client escapes a brace before sending and the whole point is what
// an agent that does not can make the proxy do.
func rawProxyRequest(t *testing.T, proxyHost, requestLine, hostHeader, tunnelTo string) (*http.Response, string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyHost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	reader := bufio.NewReader(conn)

	if tunnelTo != "" {
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			tunnelTo, tunnelTo, testProxyAuth)
		established, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		if established.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT = %d", established.StatusCode)
		}
	}

	fmt.Fprintf(conn, "%s\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nConnection: close\r\n\r\n",
		requestLine, hostHeader, testProxyAuth)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(payload)
}

// base64("x-agent-vault:agv_tok")
const testProxyAuth = "eC1hZ2VudC12YXVsdDphZ3ZfdG9r"

func newRequestTargetFixture(t *testing.T, prefixes []string) (proxyHost, upstreamHost string) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(echoed{Path: r.URL.EscapedPath()})
	}))
	t.Cleanup(upstream.Close)
	uu, _ := url.Parse(upstream.URL)
	upstreamHost = "127.0.0.1:" + uu.Port()

	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{transport: newUpstreamTransport(), ca: newCaManager(key, cert)}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(fixedResolver{services: []*resolvedService{
		policyService(upstreamHost, nil, prefixes, nil, []substitution{
			{placeholder: "{{PAT}}", surfaces: map[string]bool{surfacePath: true}, value: []byte("ghp_real")},
		}),
	}}, ps.pollInterval)

	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)
	fu, _ := url.Parse(front.URL)
	return fu.Host, upstreamHost
}

// One literal brace used to make Go rebuild the path, dropping the '%2F' the prefix check refuses, and the
// upstream received two segments where the agent sent one.
func TestALiteralBraceNoLongerHidesAnEscapedSlash(t *testing.T) {
	proxyHost, upstreamHost := newRequestTargetFixture(t, []string{"/repos"})

	resp, _ := rawProxyRequest(t, proxyHost,
		fmt.Sprintf("GET http://%s/repos/a%%2Fb/{x} HTTP/1.1", upstreamHost), upstreamHost, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAPlaceholderInThePathStillSubstitutes(t *testing.T) {
	proxyHost, upstreamHost := newRequestTargetFixture(t, []string{"/repos"})

	resp, payload := rawProxyRequest(t, proxyHost,
		fmt.Sprintf("GET http://%s/repos/{{PAT}} HTTP/1.1", upstreamHost), upstreamHost, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, payload)
	}
	var got echoed
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("upstream did not echo JSON (%v): %s", err, payload)
	}
	if got.Path != "/repos/ghp_real" {
		t.Errorf("upstream saw %q, want the substituted path", got.Path)
	}
}

// 'http:admin/secrets' parses to an empty path and a non-empty Opaque. handlePlainForward refuses the shape,
// the tunnel reaches forwardHTTP directly, and the upstream would have received a target with no leading
// slash and a real credential on it.
func TestAnOpaqueRequestTargetIsRefusedInsideATunnel(t *testing.T) {
	proxyHost, upstreamHost := newRequestTargetFixture(t, nil)

	resp, _ := rawProxyRequest(t, proxyHost, "GET http:admin/secrets HTTP/1.1", upstreamHost, upstreamHost)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// The same two cases through a real CONNECT + TLS tunnel, which is how an agent actually arrives. The raw
// dial is still required: a Go client escapes the brace before sending, which is the bug's blind spot.
func TestTheRequestTargetHoldsThroughATLSTunnel(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(echoed{Path: r.URL.EscapedPath()})
	}))
	defer upstream.Close()
	uu, _ := url.Parse(upstream.URL)
	upstreamHost := "127.0.0.1:" + uu.Port()

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	transport := newUpstreamTransport()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}

	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{transport: transport, ca: newCaManager(key, cert)}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(fixedResolver{services: []*resolvedService{
		policyService(upstreamHost, nil, []string{"/repos"}, nil, []substitution{
			{placeholder: "{{PAT}}", surfaces: map[string]bool{surfacePath: true}, value: []byte("ghp_real")},
		}),
	}}, ps.pollInterval)
	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	defer front.Close()
	fu, _ := url.Parse(front.URL)

	clientPool := x509.NewCertPool()
	clientPool.AddCert(cert)

	send := func(target string) (int, string) {
		conn, err := net.Dial("tcp", fu.Host)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			upstreamHost, upstreamHost, testProxyAuth)
		reader := bufio.NewReader(conn)
		if established, err := http.ReadResponse(reader, nil); err != nil || established.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT failed: %v", err)
		}

		tlsConn := tls.Client(conn, &tls.Config{RootCAs: clientPool, ServerName: "127.0.0.1"})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, upstreamHost)
		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(payload)
	}

	if status, _ := send("/repos/a%2Fb/{x}"); status != http.StatusForbidden {
		t.Errorf("an escaped slash beside a brace = %d, want 403", status)
	}

	status, payload := send("/repos/{{PAT}}")
	if status != http.StatusOK {
		t.Fatalf("placeholder = %d, want 200: %s", status, payload)
	}
	var got echoed
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("upstream did not echo JSON (%v): %s", err, payload)
	}
	if got.Path != "/repos/ghp_real" {
		t.Errorf("upstream saw %q, want the substituted path", got.Path)
	}
}
