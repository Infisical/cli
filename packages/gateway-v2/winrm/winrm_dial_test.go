package winrm

import (
	"context"
	"io"
	"net"
	"testing"
)

func TestBoundedDialCapsReadsPerConnection(t *testing.T) {
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
