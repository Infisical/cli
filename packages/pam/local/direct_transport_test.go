package pam

import (
	"net"
	"testing"
)

func TestCreateRelayConnectionUsesDirectAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	server := &BaseProxyServer{}
	conn, err := server.createRelayConnectionWith(LiveSession{DirectAddress: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	transport, ok := conn.(*gatewayTransportConn)
	if !ok || !transport.direct {
		t.Fatalf("expected a direct gateway transport, got %T", conn)
	}

	peer := <-accepted
	peer.Close()
}

func TestCreateRelayConnectionRequiresFallbackAfterDirectFailure(t *testing.T) {
	server := &BaseProxyServer{}
	if _, err := server.createRelayConnectionWith(LiveSession{DirectAddress: "127.0.0.1:1"}); err == nil {
		t.Fatal("expected direct connection failure without a relay fallback")
	}
}

func TestDirectRetriedWhenThereIsNoRelay(t *testing.T) {
	server := &BaseProxyServer{}
	session := LiveSession{DirectAddress: "127.0.0.1:1"}

	// The flag must not latch and skip the only transport the session has.
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := server.createRelayConnectionWith(session); err == nil {
			t.Fatal("expected direct connection failure without a relay fallback")
		}
		if server.skipDirect(session) {
			t.Fatal("direct must stay eligible when it is the only transport")
		}
	}
}

func TestDirectSkippedForLaterConnectionsOnceItFails(t *testing.T) {
	server := &BaseProxyServer{}
	// The relay is never dialled: it fails on missing certs, which still proves direct was skipped.
	session := LiveSession{DirectAddress: "127.0.0.1:1", RelayHost: "relay.invalid:8443"}

	if server.skipDirect(session) {
		t.Fatal("direct should be tried on the first connection")
	}

	_, _ = server.createRelayConnectionWith(session)

	if !server.skipDirect(session) {
		t.Fatal("a failed direct dial should take direct out of play for later connections")
	}
}

func TestDirectStaysEligibleForADifferentSessionWithoutARelay(t *testing.T) {
	server := &BaseProxyServer{}
	withRelay := LiveSession{DirectAddress: "127.0.0.1:1", RelayHost: "relay.invalid:8443"}
	_, _ = server.createRelayConnectionWith(withRelay)

	// skipDirect is gated on a relay being available, so a session with none still tries direct.
	if server.skipDirect(LiveSession{DirectAddress: "127.0.0.1:1"}) {
		t.Fatal("direct must stay eligible when the session has no relay to fall back to")
	}
}

func TestDirectRetriedWhenARefreshedSessionCarriesANewAddress(t *testing.T) {
	server := &BaseProxyServer{}
	session := LiveSession{DirectAddress: "127.0.0.1:1", RelayHost: "relay.invalid:8443"}
	_, _ = server.createRelayConnectionWith(session)

	if !server.skipDirect(session) {
		t.Fatal("the address that failed should stay out of play")
	}

	// An agent proxy outlives its session, so a new address must not inherit the old failure.
	refreshed := LiveSession{DirectAddress: "127.0.0.1:2", RelayHost: "relay.invalid:8443"}
	if server.skipDirect(refreshed) {
		t.Fatal("a new direct address deserves its own attempt")
	}
}
