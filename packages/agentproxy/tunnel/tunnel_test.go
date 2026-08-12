package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// pair wires a Serve side and a Client side over an in-memory connection, which is enough to exercise the
// multiplexing without a relay, a gateway, or TLS.
func pair(t *testing.T, handle func(net.Conn)) *Client {
	t.Helper()

	serverConn, clientConn := net.Pipe()

	go func() {
		// Serve is handed the connection's buffered reader because the HTTP/2 preface may already have been
		// read into it during ALPN negotiation; passing the raw conn would lose those bytes.
		_ = Serve(serverConn, bufio.NewReader(serverConn), handle)
	}()

	client, err := NewClient(clientConn)
	if err != nil {
		t.Fatalf("failed to start the tunnel client: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	return client
}

func TestStreamRoundTrip(t *testing.T) {
	client := pair(t, func(stream net.Conn) {
		defer stream.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(stream, buf); err != nil {
			return
		}
		stream.Write(append([]byte("echo:"), buf...))
	})

	stream, err := client.Open(context.Background())
	if err != nil {
		t.Fatalf("failed to open a stream: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	buf := make([]byte, 10)
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("failed to read the reply: %v", err)
	}
	if string(buf) != "echo:hello" {
		t.Fatalf("expected %q, got %q", "echo:hello", string(buf))
	}
}

// Many tunnels over one connection is the whole point: a connection per CONNECT would cost three handshakes
// each, and agents open many short-lived tunnels.
func TestConcurrentStreamsAreIndependent(t *testing.T) {
	client := pair(t, func(stream net.Conn) {
		defer stream.Close()
		reader := bufio.NewReader(stream)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		stream.Write([]byte(line))
	})

	const streams = 16
	var wg sync.WaitGroup
	errs := make(chan error, streams)

	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			stream, err := client.Open(context.Background())
			if err != nil {
				errs <- fmt.Errorf("stream %d: open: %w", n, err)
				return
			}
			defer stream.Close()

			want := fmt.Sprintf("stream-%d\n", n)
			if _, err := stream.Write([]byte(want)); err != nil {
				errs <- fmt.Errorf("stream %d: write: %w", n, err)
				return
			}

			got, err := bufio.NewReader(stream).ReadString('\n')
			if err != nil {
				errs <- fmt.Errorf("stream %d: read: %w", n, err)
				return
			}
			// Each stream must get its own reply back, not another stream's.
			if got != want {
				errs <- fmt.Errorf("stream %d: expected %q, got %q", n, want, got)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// A streamed response has to arrive incrementally. If the writer buffered until the handler returned, an agent
// consuming server-sent events would see nothing until the end, which is the failure mode this guards.
func TestWritesArriveBeforeTheHandlerReturns(t *testing.T) {
	release := make(chan struct{})

	client := pair(t, func(stream net.Conn) {
		defer stream.Close()
		stream.Write([]byte("first\n"))
		// Held open deliberately: the client must already have "first" while the handler is still running.
		<-release
		stream.Write([]byte("second\n"))
	})

	stream, err := client.Open(context.Background())
	if err != nil {
		t.Fatalf("failed to open a stream: %v", err)
	}
	defer stream.Close()

	reader := bufio.NewReader(stream)
	done := make(chan string, 1)
	go func() {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			done <- ""
			return
		}
		done <- line
	}()

	select {
	case got := <-done:
		if got != "first\n" {
			t.Fatalf("expected the first chunk, got %q", got)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("the first chunk never arrived, so writes are being buffered until the handler returns")
	}

	close(release)
}

func TestLargePayloadSurvivesTheWindow(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4<<20)

	client := pair(t, func(stream net.Conn) {
		defer stream.Close()
		io.Copy(stream, stream)
	})

	stream, err := client.Open(context.Background())
	if err != nil {
		t.Fatalf("failed to open a stream: %v", err)
	}
	defer stream.Close()

	go func() {
		stream.Write(payload)
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("failed to read the payload back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the payload came back corrupted")
	}
}

// A dead multiplexer must fail new streams rather than hang, so an agent gets an error it can act on instead
// of stalling forever.
func TestOpenFailsAfterClose(t *testing.T) {
	client := pair(t, func(stream net.Conn) { stream.Close() })
	client.Close()

	if _, err := client.Open(context.Background()); err == nil {
		t.Fatal("expected opening a stream on a closed tunnel to fail")
	}
}
