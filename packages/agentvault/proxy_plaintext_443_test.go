package agentvault

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A service that names no port defaults to 443, which everywhere else means TLS. Both cases below reach the
// proxy as plain HTTP on that port: a CONNECT tunnel that never handshakes, and an http:// URL naming 443.
// Neither is something a correct client produces, and before the guard both had the credential attached and
// sent upstream in the clear. The refusal fires before any dial, so the fixture needs no live upstream.
func newPlaintext443Fixture(t *testing.T) (proxyHost, serviceHost string) {
	t.Helper()
	serviceHost = "example.test"

	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{transport: newUpstreamTransport(), ca: newCaManager(key, cert)}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(fixedResolver{services: []*resolvedService{
		policyService(serviceHost, nil, nil, nil, []substitution{
			{placeholder: "{{PAT}}", surfaces: map[string]bool{surfacePath: true}, value: []byte("ghp_real")},
		}),
	}}, ps.pollInterval)

	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)
	fu, _ := url.Parse(front.URL)
	return fu.Host, serviceHost
}

func TestPlainHTTPInsideA443TunnelIsRefused(t *testing.T) {
	proxyHost, serviceHost := newPlaintext443Fixture(t)

	conn, err := net.Dial("tcp", proxyHost)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Authorization: Basic %s\r\n\r\n",
		serviceHost, serviceHost, testProxyAuth)
	established, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if established.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %d", established.StatusCode)
	}

	// Plain HTTP down the tunnel rather than a TLS handshake — the shape the guard exists for.
	fmt.Fprintf(conn, "GET /repos/{{PAT}} HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", serviceHost)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAbsoluteFormHTTPToPort443IsRefused(t *testing.T) {
	proxyHost, serviceHost := newPlaintext443Fixture(t)

	resp, body := rawProxyRequest(t, proxyHost,
		fmt.Sprintf("GET http://%s:443/repos/{{PAT}} HTTP/1.1", serviceHost), serviceHost+":443", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "expects TLS") {
		t.Errorf("body %q does not name the reason", body)
	}
}
