package agentproxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TRACE (and TRACK) make an upstream echo the request — including the injected credential — back in the
// response, so the proxy must reject them rather than forward.
func TestTraceMethodRejected(t *testing.T) {
	client := newTestProxy(t, UnmatchedAllow, nil)

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(client, "TRACE http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: %s\r\n\r\n",
		proxySecretHeader(testProxySecret)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for TRACE, got %d", resp.StatusCode)
	}
}

type reflectingTransport struct{ header http.Header }

func (rt reflectingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusFound,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     rt.header,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

// The proxy injects one-way and relays the response untouched; reflected request data passes through by design.
func TestForwardPassesResponseHeadersThrough(t *testing.T) {
	services := []*resolvedService{{
		name:         "svc",
		hostPatterns: parseHostPatterns("example.com"),
		isEnabled:    true,
		credentials: []resolvedCredential{
			{role: roleHeaderRewrite, headerName: "Authorization", headerPrefix: "Bearer", value: "real_secret"},
		},
	}}
	respHeader := make(http.Header)
	respHeader.Set("Location", "https://example.com/next?token=real_secret")
	ps := &proxyServer{
		opts:      Options{UnmatchedHost: UnmatchedAllow},
		session:   testSession(),
		bundles:   staticResolver{services_: services},
		transport: reflectingTransport{header: respHeader},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp, _, err := ps.forward(req, "http", "example.com", "80")
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if got := resp.Header.Get("Location"); got != "https://example.com/next?token=real_secret" {
		t.Fatalf("response header should pass through unchanged, got %q", got)
	}
}
