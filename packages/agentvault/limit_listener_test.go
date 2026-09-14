package agentvault

import (
	"net"
	"testing"
	"time"
)

func TestClosingASaturatedLimiterWakesAccept(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll := newLimitListener(raw, 1, func() {})

	dial, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	held, err := ll.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	accepted := make(chan error, 1)
	go func() { _, err := ll.Accept(); accepted <- err }()
	time.Sleep(50 * time.Millisecond)

	_ = ll.Close()
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("Accept returned a connection from a closed listener")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept stayed parked on the semaphore after Close, so shutdown would wait out its deadline")
	}
}

func TestReleasingAConnectionFreesTheSlot(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll := newLimitListener(raw, 1, func() {})
	defer ll.Close()

	for i := 0; i < 3; i++ {
		dial, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn, err := ll.Accept()
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		_ = conn.Close()
		_ = dial.Close()
	}
}
