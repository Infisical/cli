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
