package agentproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// newLocalTestProxy builds a local-mode proxyServer with an injected snapshot, mirroring
// newTestProxy's pipe/one-shot-listener harness for the remote tests.
func newLocalTestProxy(t *testing.T, local *LocalOptions, services []*resolvedService, rt http.RoundTripper) net.Conn {
	t.Helper()
	resolver := newLocalResolver(local)
	resolver.services = services
	resolver.valid = true
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow, Local: local},
		cache:     resolver,
		transport: rt,
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

func TestLocalCaMintsVerifiableLeaves(t *testing.T) {
	ca, err := newLocalCaManager()
	if err != nil {
		t.Fatal(err)
	}

	rootPEM := ca.RootPEM()
	if len(rootPEM) == 0 {
		t.Fatal("expected a root PEM from the local CA")
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		t.Fatal("root PEM did not decode")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsCA {
		t.Fatal("local root is not a CA certificate")
	}
	pub, ok := root.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("local root must be ECDSA P-256, got %T", root.PublicKey)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("local root is not self-signed: %v", err)
	}

	leaf, err := ca.mintLeaf("api.stripe.com")
	if err != nil {
		t.Fatal(err)
	}
	parsedLeaf, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := parsedLeaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "api.stripe.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify against the local root: %v", err)
	}

	if newCaManager(func() string { return "" }).RootPEM() != nil {
		t.Fatal("remote caManager must not expose a root PEM")
	}
}

func TestLocalResolverSnapshotLifecycle(t *testing.T) {
	local := &LocalOptions{
		ProjectID: "proj", Environment: "prod", SecretPath: "/",
		UserToken:  func() string { t.Fatal("token must not be used without a snapshot refresh"); return "" },
		IdentityID: "user-1", IdentityName: "dev",
	}
	r := newLocalResolver(local)

	// Without a snapshot, refreshActive must be a no-op (it must not call the API).
	r.refreshActive()

	r.services = []*resolvedService{{name: "svc"}}
	r.valid = true

	got, err := r.get("ignored-wire-credential", agentScope{projectID: "other"})
	if err != nil || len(got) != 1 || got[0].name != "svc" {
		t.Fatalf("get should return the snapshot regardless of wire args, got %v, %v", got, err)
	}

	id, name, ok := r.identity("", agentScope{})
	if !ok || id != "user-1" || name != "dev" {
		t.Fatalf("identity should be the configured user, got %q %q %v", id, name, ok)
	}

	if len(r.activeJWTs()) != 0 {
		t.Fatal("local mode must register no lease JWTs")
	}

	r.close()
	if r.valid || r.services != nil {
		t.Fatal("close must drop the snapshot (fail closed)")
	}
}

func TestLocalModeServesWithoutProxyAuth(t *testing.T) {
	local := &LocalOptions{
		ProjectID: "proj", Environment: "prod", SecretPath: "/",
		UserToken: func() string { return "dev-token" },
	}
	services := []*resolvedService{{
		name:         "stripe",
		hostPatterns: parseHostPatterns("example.com"),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}
	stub := &stubRoundTripper{respBody: "ok"}
	client := newLocalTestProxy(t, local, services, stub)
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	// No Proxy-Authorization header anywhere: local mode must serve and inject regardless.
	if _, err := fmt.Fprintf(client, "GET http://example.com/v1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.gotAuth) != 1 || stub.gotAuth[0] != "Bearer real_secret" {
		t.Fatalf("expected injected credential, got %v", stub.gotAuth)
	}
}

func TestRemoteModeChallengesWithoutProxyAuth(t *testing.T) {
	cache := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow},
		cache:     cache,
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
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := fmt.Fprintf(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407 in remote mode, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") != "Basic" {
		t.Fatal("expected a Proxy-Authenticate challenge")
	}
}

func TestUnmatchedBlockRespectsAllowHost(t *testing.T) {
	local := &LocalOptions{
		ProjectID: "proj", Environment: "prod", SecretPath: "/",
		UserToken: func() string { return "dev-token" },
	}
	resolver := newLocalResolver(local)
	resolver.services = nil // no proxied services: every host is "unmatched"
	resolver.valid = true
	stub := &stubRoundTripper{respBody: "ok"}
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedBlock, Local: local, AllowedHosts: []string{"docs.internal"}},
		cache:     resolver,
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

	// Allowlisted host passes through (case-insensitive) even under block.
	if _, err := fmt.Fprintf(client, "GET http://Docs.Internal/x HTTP/1.1\r\nHost: docs.internal\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted host should pass through under block, got %d", resp.StatusCode)
	}
}

func TestUnmatchedBlockRejectsNonAllowlistedHost(t *testing.T) {
	local := &LocalOptions{
		ProjectID: "proj", Environment: "prod", SecretPath: "/",
		UserToken: func() string { return "dev-token" },
	}
	resolver := newLocalResolver(local)
	resolver.valid = true
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedBlock, Local: local, AllowedHosts: []string{"docs.internal"}},
		cache:     resolver,
		transport: &stubRoundTripper{respBody: "ok"},
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

	if _, err := fmt.Fprintf(client, "GET http://evil.example/x HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-allowlisted host should be blocked, got %d", resp.StatusCode)
	}
}

func TestProxyLifecycleServeShutdown(t *testing.T) {
	p, err := New(Options{
		UnmatchedHost: UnmatchedAllow,
		Local: &LocalOptions{
			ProjectID: "proj", Environment: "prod", SecretPath: "/",
			UserToken: func() string { return "" },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.LocalRootPEM()) == 0 {
		t.Fatal("expected a local root PEM in local mode")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.Serve(ln) }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("proxy is not accepting on %s: %v", ln.Addr(), err)
	}
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned an error after Shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}

	// Shutdown is idempotent.
	if err := p.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
