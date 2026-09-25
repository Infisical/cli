package agentvault

import (
	"net/http"
	"testing"
)

// Connection names the headers meant for this hop alone, and the same function runs on responses,
// where it is the upstream saying a header is not for the agent.
func TestConnectionListedHeadersAreStripped(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Hop, Keep-Alive")
	h.Add("Connection", "X-Second")
	h.Set("X-Hop", "for the proxy only")
	h.Set("X-Second", "also for the proxy")
	h.Set("X-Kept", "for the upstream")
	h.Set("Keep-Alive", "timeout=5")

	stripHopByHopHeaders(h)

	for _, name := range []string{"Connection", "X-Hop", "X-Second", "Keep-Alive"} {
		if got := h.Get(name); got != "" {
			t.Errorf("%s survived as %q", name, got)
		}
	}
	if got := h.Get("X-Kept"); got != "for the upstream" {
		t.Errorf("an unlisted header must survive, got %q", got)
	}
}

// Stripping runs before injection, so naming the credential's header in Connection cannot delete it.
// Go documents the reverse ordering as the reason ReverseProxy.Director is deprecated.
func TestConnectionCannotDeleteTheInjectedCredential(t *testing.T) {
	for _, tc := range []struct{ name, header string }{
		{"the default header", "Authorization"},
		{"a custom header", "X-Api-Key"},
	} {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.Header.Set("Connection", tc.header)
		req.Header.Set(tc.header, "agent-supplied")

		stripHopByHopHeaders(req.Header)
		if got := req.Header.Get(tc.header); got != "" {
			t.Fatalf("%s: the agent's own value should have been stripped, got %q", tc.name, got)
		}

		cred := &credential{kind: credentialBearer, headerName: tc.header, headerPrefix: "Bearer", value: []byte("real")}
		injectCredential(req, cred)
		if got := req.Header.Get(tc.header); got != "Bearer real" {
			t.Fatalf("%s: the injected credential must survive, got %q", tc.name, got)
		}
	}
}
