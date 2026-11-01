package agentproxy

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A client sending a header block larger than maxRequestHeaderBytes (before auth) must be rejected
// with 431 rather than allowed to grow proxy memory unbounded.
func TestOversizedRequestHeadersRejected(t *testing.T) {
	jwt := "test.jwt.token"
	scope := agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
	client := newTestProxy(t, UnmatchedAllow, jwt, scope, nil)

	go func() {
		huge := strings.Repeat("a", maxRequestHeaderBytes+4096)
		_, _ = fmt.Fprintf(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Big: %s\r\n\r\n", huge)
	}()

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("expected a 431 response, got read error: %v", err)
	}
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode)
	}
}
