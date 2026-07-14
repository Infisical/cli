package agentproxy

import (
	"net"
	"testing"
	"time"
)

// limitListener must cap concurrent accepted connections: at capacity, Accept does not yield a new
// connection until a previously accepted one is closed and frees its slot.
func TestLimitListenerCapsConcurrentConns(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	ll := newLimitListener(base, 1)
	addr := base.Addr().String()

	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	c1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	var a1 net.Conn
	select {
	case a1 = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("first connection was not accepted")
	}

	// The TCP connect may complete via the kernel backlog, but Accept must not yield it while at capacity.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	select {
	case <-accepted:
		t.Fatal("second connection accepted while at capacity")
	case <-time.After(300 * time.Millisecond):
	}

	// Freeing the first slot lets the second through.
	_ = a1.Close()
	select {
	case a2 := <-accepted:
		_ = a2.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("second connection not accepted after slot freed")
	}
}
