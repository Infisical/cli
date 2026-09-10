package agentvault

import "testing"

// ForceAttemptHTTP2: false does not disable h2 on its own, so the empty map beside it is what keeps
// the upstream on HTTP/1.1. It looks redundant and is not; verified against a live h2 origin, which
// answers HTTP/2 without it and HTTP/1.1 with it.
func TestUpstreamTransportKeepsHTTP2Off(t *testing.T) {
	tr := newUpstreamTransport()
	if tr.TLSNextProto == nil {
		t.Fatal("TLSNextProto must be a non-nil empty map, or the transport negotiates h2")
	}
	if len(tr.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto must be empty, has %d entries", len(tr.TLSNextProto))
	}
}
