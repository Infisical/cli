package agentproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/agentproxy/tunnel"
)

// recordingConn keeps a copy of every byte that crossed it, so a test can assert what a credential did and
// did not travel over.
type recordingConn struct {
	net.Conn
	mu    sync.Mutex
	seen  bytes.Buffer
	seen2 bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.seen.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.seen2.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) contains(needle string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Contains(c.seen.Bytes(), []byte(needle)) || bytes.Contains(c.seen2.Bytes(), []byte(needle))
}

// This is the claim the whole feature rests on: the agent's traffic reaches the upstream carrying the real
// credential, and the credential never crosses the agent's own connection. Everything here is in-process: an
// upstream, a broker on the far side of a tunnel, and a real http.Client that only knows about a proxy.
func TestBrokeredCredentialReachesUpstreamButNeverTheAgentsConnection(t *testing.T) {
	const realSecret = "sk_live_real_credential_value"

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

	session := *testSession()
	services := []*resolvedService{{
		id:           "svc-1",
		name:         "billing",
		hostPatterns: parseHostPatterns(u.Hostname()),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: realSecret, secretKey: "STRIPE_KEY"},
		},
	}}

	// The broker side of the tunnel. Constructed directly rather than through NewBroker so the test supplies
	// the resolved bundle instead of a backend.
	broker := &Broker{
		shared: &proxyServer{
			opts:         Options{UnmatchedHost: UnmatchedAllow},
			transport:    &http.Transport{},
			usageTracker: newUsageTracker(),
			bundles:      staticResolver{services_: services},
		},
		bundles: newBundleResolver(func() string { return "" }, 0),
		stop:    make(chan struct{}),
	}
	defer close(broker.stop)

	// In production this connection is relay + nested mTLS. What matters for the claim is that it is a
	// different connection from the agent's, which net.Pipe reproduces exactly.
	brokerSide, agentSide := net.Pipe()
	recorded := &recordingConn{Conn: agentSide}

	go func() {
		_ = tunnel.Serve(brokerSide, bufio.NewReader(brokerSide), func(stream net.Conn) {
			broker.ServeConn(stream, session)
		})
	}()

	client, err := tunnel.NewClient(recorded)
	if err != nil {
		t.Fatalf("failed to start the tunnel client: %v", err)
	}
	defer client.Close()

	// A real http.Client that knows nothing except that there is a proxy. Each dial to "the proxy" is one
	// tunnel stream, which is what the CLI's local listener does.
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://broker.invalid") },
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return client.Open(ctx)
			},
		},
	}

	resp, err := httpClient.Get(upstream.URL + "/v1/charges")
	if err != nil {
		t.Fatalf("request through the broker failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if len(gotAuth) != 1 {
		t.Fatalf("expected exactly one upstream request, got %d", len(gotAuth))
	}
	if gotAuth[0] != "Bearer "+realSecret {
		t.Fatalf("upstream did not receive the brokered credential, got %q", gotAuth[0])
	}
	// The point of the whole design: the credential was applied on the far side, so it never appeared on the
	// connection the agent holds.
	if recorded.contains(realSecret) {
		t.Fatal("the real credential crossed the agent's own connection; brokering is not confining it")
	}
}

// The HTTPS path, which is the one agents actually take: CONNECT, MITM, then a request inside the tunnel,
// all of it over a multiplexed stream. This is what a plain-HTTP test cannot catch, because CONNECT hijacks
// the connection and ServeConn has to stay alive across the hijack or the stream dies under the handshake.
func TestBrokerServesConnectOverATunnelStream(t *testing.T) {
	const realSecret = "sk_live_connect_path"

	ca, interCert := newTestCA(t)
	stub := &stubRoundTripper{respBody: "ok"}

	services := []*resolvedService{{
		id:           "svc-1",
		name:         "billing",
		hostPatterns: parseHostPatterns("example.com"),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: realSecret},
		},
	}}

	broker := &Broker{
		shared: &proxyServer{
			opts:         Options{UnmatchedHost: UnmatchedAllow},
			ca:           ca,
			transport:    stub,
			usageTracker: newUsageTracker(),
			bundles:      staticResolver{services_: services},
		},
		bundles: newBundleResolver(func() string { return "" }, 0),
		stop:    make(chan struct{}),
	}
	defer close(broker.stop)

	session := *testSession()
	brokerSide, agentSide := net.Pipe()
	recorded := &recordingConn{Conn: agentSide}

	go func() {
		_ = tunnel.Serve(brokerSide, bufio.NewReader(brokerSide), func(stream net.Conn) {
			broker.ServeConn(stream, session)
		})
	}()

	client, err := tunnel.NewClient(recorded)
	if err != nil {
		t.Fatalf("failed to start the tunnel client: %v", err)
	}
	defer client.Close()

	stream, err := client.Open(context.Background())
	if err != nil {
		t.Fatalf("failed to open a stream: %v", err)
	}
	defer stream.Close()

	if _, err := fmt.Fprintf(stream, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("failed to write CONNECT: %v", err)
	}

	established := "HTTP/1.1 200 Connection Established\r\n\r\n"
	buf := make([]byte, len(established))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("reading the CONNECT response: %v", err)
	}
	if string(buf) != established {
		t.Fatalf("unexpected CONNECT response: %q", buf)
	}

	pool := x509.NewCertPool()
	pool.AddCert(interCert)
	tlsClient := tls.Client(stream, &tls.Config{ServerName: "example.com", RootCAs: pool})
	// The handshake is the assertion: it can only complete if ServeConn kept the stream open past the hijack.
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("MITM TLS handshake through the tunnel failed: %v", err)
	}

	if _, err := io.WriteString(tlsClient, "GET /v1/charges HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("failed to write the tunneled request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("reading the tunneled response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.gotAuth) != 1 || stub.gotAuth[0] != "Bearer "+realSecret {
		t.Fatalf("upstream did not receive the brokered credential: %v", stub.gotAuth)
	}
	if recorded.contains(realSecret) {
		t.Fatal("the real credential crossed the agent's own connection")
	}
}
