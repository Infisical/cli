package agentproxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestCA builds a caManager with a locally self-signed intermediate so mintLeaf works offline
// (ensureIntermediate skips the API when an unexpired intermediate is already set). Returns the
// intermediate cert so the client can trust the minted leaf chain.
func newTestCA(t *testing.T) (*caManager, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-intermediate"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &caManager{
		intermediateKey:  key,
		intermediateCert: cert,
		intermediateExp:  cert.NotAfter,
		leafCache:        make(map[string]*leafEntry),
	}, cert
}

// stubRoundTripper records the Authorization header of each forwarded request and returns a canned 200,
// so the tunnel path can be exercised without a live TLS upstream.
type stubRoundTripper struct {
	mu       sync.Mutex
	gotAuth  []string
	respBody string
}

func (s *stubRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.gotAuth = append(s.gotAuth, r.Header.Get("Authorization"))
	s.mu.Unlock()
	return &http.Response{
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(s.respBody)),
		ContentLength: int64(len(s.respBody)),
		Request:       r,
	}, nil
}

// Drives a full CONNECT → TLS-terminate → tunneled HTTP request through the new http.Server machinery
// (hijack, one-shot listener, inner server) and asserts credentials are injected and keep-alive works.
func TestConnectTunnelInjectsCredentialsAndKeepsAlive(t *testing.T) {
	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		name:         "stripe",
		hostPatterns: parseHostPatterns("example.com"),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}

	ca, interCert := newTestCA(t)
	stub := &stubRoundTripper{respBody: "ok"}
	cache := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{jwt: jwt, scope: scope, services: services, lastSeen: time.Now()}
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow},
		ca:        ca,
		cache:     cache,
		transport: stub,
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

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. CONNECT and read the raw tunnel-established response (exact bytes, so we don't consume TLS data).
	_, err := fmt.Fprintf(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: %s\r\n\r\n",
		proxyAuthHeader("proj", "prod", "/", jwt))
	if err != nil {
		t.Fatal(err)
	}
	established := "HTTP/1.1 200 Connection Established\r\n\r\n"
	buf := make([]byte, len(established))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	if string(buf) != established {
		t.Fatalf("unexpected CONNECT response: %q", buf)
	}

	// 2. TLS handshake against the MITM leaf, trusting our local intermediate.
	pool := x509.NewCertPool()
	pool.AddCert(interCert)
	tlsClient := tls.Client(client, &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// 3. Two tunneled requests over the same connection (keep-alive), asserting credential injection.
	reader := bufio.NewReader(tlsClient)
	for i := 0; i < 2; i++ {
		if _, err := io.WriteString(tlsClient, "GET /v1/charges HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
			t.Fatalf("writing tunneled request %d: %v", i, err)
		}
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("reading tunneled response %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.gotAuth) != 2 {
		t.Fatalf("expected 2 forwarded requests, got %d", len(stub.gotAuth))
	}
	for i, auth := range stub.gotAuth {
		if auth != "Bearer real_secret" {
			t.Fatalf("request %d: expected injected 'Bearer real_secret', got %q", i, auth)
		}
	}
}

// A CONNECT with no Proxy-Authorization must be answered with 407 (and the Basic challenge) before any
// hijack — exercising the pre-hijack error path through the ResponseWriter.
func TestConnectRequiresProxyAuth(t *testing.T) {
	ca, _ := newTestCA(t)
	cache := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow},
		ca:        ca,
		cache:     cache,
		transport: &stubRoundTripper{},
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

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != "Basic" {
		t.Fatalf("expected Proxy-Authenticate: Basic, got %q", got)
	}
}
