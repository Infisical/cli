package agentproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

// serveTestProxy serves ps over an in-memory pipe (one connection) and returns the client end,
// mirroring newTestProxy's harness for the remote tests.
func serveTestProxy(t *testing.T, ps *proxyServer) net.Conn {
	t.Helper()
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

// newLocalTestProxy builds a local-mode proxyServer with an injected snapshot and serves it.
func newLocalTestProxy(t *testing.T, local *LocalOptions, services []*resolvedService, rt http.RoundTripper) net.Conn {
	t.Helper()
	resolver := newLocalResolver(local, newLeaseStore(func() string { return "" }))
	resolver.services = services
	resolver.valid = true
	return serveTestProxy(t, &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow, Local: local},
		resolver:  resolver,
		transport: rt,
	})
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
	r := newLocalResolver(local, newLeaseStore(func() string { return "" }))

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

	// With a live snapshot the lease loop must see exactly one key, and it must be the key derived from
	// the empty wire JWT plus the fixed scope, or registered leases would never be renewed.
	live := r.activeJWTs()
	if len(live) != 1 {
		t.Fatalf("expected exactly one live lease key, got %d", len(live))
	}
	if _, ok := live[cacheKey("", local.scope())]; !ok {
		t.Fatalf("live key must match the registered leaseKey scope, got %v", live)
	}

	r.close()
	if r.valid || r.services != nil {
		t.Fatal("close must drop the snapshot (fail closed)")
	}
	// Fail closed applies to leases too: no snapshot means no renewal.
	if len(r.activeJWTs()) != 0 {
		t.Fatal("a dropped snapshot must stop lease renewal")
	}
}

// resolveSnapshot must register a lease for a leasable dynamic credential, and skip one the developer
// cannot lease rather than registering a lease that could never be minted.
func TestLocalResolverRegistersLeasableDynamicCredentials(t *testing.T) {
	origURL := config.INFISICAL_URL
	stubAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/proxied-services") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ListProxiedServicesResponse{
			ProjectSlug: "my-project",
			Services: []api.ProxiedService{{
				Name:        "db-api",
				HostPattern: "db.internal",
				IsEnabled:   true,
				Credentials: []api.ProxiedServiceCredential{
					{
						Role:               "header-rewrite",
						HeaderName:         "Authorization",
						DynamicSecretName:  "leasable-pg",
						DynamicSecretField: "DB_PASSWORD",
						CallerCanLease:     true,
					},
					{
						Role:               "header-rewrite",
						HeaderName:         "X-Other",
						DynamicSecretName:  "forbidden-pg",
						DynamicSecretField: "DB_PASSWORD",
						CallerCanLease:     false,
					},
				},
			}},
		})
	}))
	defer stubAPI.Close()
	config.INFISICAL_URL = stubAPI.URL
	defer func() { config.INFISICAL_URL = origURL }()

	local := &LocalOptions{
		ProjectID: "proj", Environment: "prod", SecretPath: "/",
		UserToken: func() string { return "dev-token" },
	}
	leases := &leaseStore{entries: make(map[leaseKey]*leaseEntry), wake: make(chan struct{}, 1)}
	resolver := newLocalResolver(local, leases)

	services, err := resolver.resolveSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 {
		t.Fatalf("expected one service, got %d", len(services))
	}

	// Only the leasable credential survives.
	if n := len(services[0].credentials); n != 1 {
		t.Fatalf("expected only the leasable dynamic credential, got %d", n)
	}
	cred := services[0].credentials[0]
	if cred.dynamic == nil {
		t.Fatal("the surviving credential should carry a dynamic lease ref")
	}
	if cred.dynamic.key.secretName != "leasable-pg" {
		t.Errorf("wrong secret registered: %q", cred.dynamic.key.secretName)
	}
	if cred.dynamic.key.scope != local.scope() {
		t.Errorf("lease key scope must be the run's scope, got %+v", cred.dynamic.key.scope)
	}

	// The lease store must hold exactly the leasable one, under a key the refresh loop considers live.
	leases.mu.Lock()
	n := len(leases.entries)
	_, registered := leases.entries[cred.dynamic.key]
	leases.mu.Unlock()
	if n != 1 || !registered {
		t.Fatalf("expected exactly the leasable secret registered, got %d entries", n)
	}
}

// Local mode brokers dynamic secrets the same way remote mode does: the credential resolves through a
// lease minted with the developer's own token, and the minted value reaches the wire.
func TestLocalModeBrokersDynamicSecret(t *testing.T) {
	local := &LocalOptions{
		ProjectID: "proj", Environment: "prod", SecretPath: "/",
		UserToken: func() string { return "dev-token" },
	}

	var mintedWith leaseMintArgs
	var mintCalls int
	leases := &leaseStore{entries: make(map[leaseKey]*leaseEntry), wake: make(chan struct{}, 1)}
	leases.mint = func(args leaseMintArgs) (leaseMintResult, error) {
		mintCalls++
		mintedWith = args
		return leaseMintResult{
			leaseID:  "lease-1",
			expireAt: time.Now().Add(time.Hour),
			data:     map[string]interface{}{"DB_PASSWORD": "minted_secret"},
		}, nil
	}

	resolver := newLocalResolver(local, leases)

	// Register a dynamic credential exactly as resolveSnapshot would, then hand the resolver a snapshot
	// that references it.
	key := leaseKey{
		scope:      local.scope(),
		secretName: "my-postgres",
		configHash: canonicalConfigHash(nil),
	}
	leases.register(key, leaseSpec{projectSlug: "my-project", config: nil})
	resolver.services = []*resolvedService{{
		name:         "internal-db-api",
		hostPatterns: parseHostPatterns("example.com"),
		isEnabled:    true,
		credentials: []resolvedCredential{{
			role:         roleHeaderRewrite,
			headerName:   "Authorization",
			headerPrefix: "Bearer",
			dynamic:      &dynamicCredentialRef{key: key, field: "DB_PASSWORD"},
		}},
	}}
	resolver.valid = true

	stub := &stubRoundTripper{respBody: "ok"}
	client := serveTestProxy(t, &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow, Local: local},
		resolver:  resolver,
		leases:    leases,
		transport: stub,
	})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

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

	if mintCalls != 1 {
		t.Fatalf("expected the lease to be minted lazily exactly once, got %d calls", mintCalls)
	}
	if mintedWith.secretName != "my-postgres" || mintedWith.projectSlug != "my-project" {
		t.Errorf("lease minted with wrong args: %+v", mintedWith)
	}
	if mintedWith.environment != "prod" || mintedWith.path != "/" {
		t.Errorf("lease must be minted in the run's scope, got env=%q path=%q", mintedWith.environment, mintedWith.path)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.gotAuth) != 1 || stub.gotAuth[0] != "Bearer minted_secret" {
		t.Fatalf("expected the minted lease value on the wire, got %v", stub.gotAuth)
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
	client := serveTestProxy(t, &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow},
		resolver:  cache,
		transport: &http.Transport{},
	})
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
	resolver := newLocalResolver(local, newLeaseStore(func() string { return "" }))
	resolver.services = nil // no proxied services: every host is "unmatched"
	resolver.valid = true
	stub := &stubRoundTripper{respBody: "ok"}
	client := serveTestProxy(t, &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedBlock, Local: local, AllowedHosts: []string{"docs.internal"}},
		resolver:  resolver,
		transport: stub,
	})
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
	resolver := newLocalResolver(local, newLeaseStore(func() string { return "" }))
	resolver.valid = true
	client := serveTestProxy(t, &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedBlock, Local: local, AllowedHosts: []string{"docs.internal"}},
		resolver:  resolver,
		transport: &stubRoundTripper{respBody: "ok"},
	})
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
