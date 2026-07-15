package agentproxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Exercises the full production serve path over real TCP sockets (not net.Pipe): a real http.Client issues
// an HTTPS request through the proxy, which triggers CONNECT → hijack → MITM TLS → forward → real RoundTrip
// to a real TLS upstream. Asserts the injected credential reaches the upstream on the wire.
func TestConnectTunnelLiveOverTCP(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()

	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	services := []*resolvedService{{
		name:         "echo",
		hostPatterns: parseHostPatterns(host),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}

	ca, interCert := newTestCA(t)
	cache := newAgentCache(func() string { return "" })
	cache.entries[cacheKey(jwt, scope)] = &agentEntry{jwt: jwt, scope: scope, services: services, lastSeen: time.Now()}

	// Upstream transport must trust the httptest upstream's real cert (the proxy does a real TLS leg to it).
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	ps := &proxyServer{
		opts:  Options{UnmatchedHost: UnmatchedAllow},
		ca:    ca,
		cache: cache,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: upstreamPool},
			TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = ps.newFrontServer().Serve(newLimitListener(ln, maxConcurrentConns)) }()

	proxyURL, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Client trusts the MITM CA and routes through the proxy, sending Proxy-Authorization on the CONNECT.
	clientPool := x509.NewCertPool()
	clientPool.AddCert(interCert)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			ProxyConnectHeader: http.Header{"Proxy-Authorization": {proxyAuthHeader("proj", "prod", "/", jwt)}},
			TLSClientConfig:    &tls.Config{RootCAs: clientPool},
		},
	}

	resp, err := client.Get(upstream.URL + "/v1/charges")
	if err != nil {
		t.Fatalf("proxied request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	// The client never sent Authorization; the proxy injected it on the wire, so the upstream echoes it back.
	if string(body) != "Bearer real_secret" {
		t.Fatalf("upstream did not receive injected credential; got %q", body)
	}
}
