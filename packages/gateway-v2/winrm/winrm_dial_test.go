package winrm

import (
	"context"
	"io"
	"net"
	"testing"
)

func TestBoundedDialCapsASingleResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		chunk := make([]byte, 64*1024)
		for {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	}()

	conn, err := boundedDial(context.Background())("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	n, err := io.Copy(io.Discard, conn)
	if err == nil {
		t.Fatalf("expected the read to fail at the cap, read %d bytes", n)
	}
	if n > maxWinRMReadBytes {
		t.Fatalf("read %d bytes, past the %d cap", n, maxWinRMReadBytes)
	}
}

func TestBoundedDialResetsTheCapForEachRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	chunk := 1024 * 1024
	responses := (maxWinRMReadBytes / chunk) + 4
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		body := make([]byte, chunk)
		for i := 0; i < responses; i++ {
			if _, err := conn.Read(buf); err != nil {
				return
			}
			if _, err := conn.Write(body); err != nil {
				return
			}
		}
	}()

	conn, err := boundedDial(context.Background())("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := make([]byte, chunk)
	for i := 0; i < responses; i++ {
		if _, err := conn.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("response %d failed after %d MiB in total: %v", i, i, err)
		}
	}
}
