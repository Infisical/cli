package agentvault

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// slowTransport holds every upstream round trip, so a client's half-close always arrives while its request is
// still in flight, which is when net/http used to cancel it.
type slowTransport struct {
	next  http.RoundTripper
	delay time.Duration
}

func (s slowTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case <-time.After(s.delay):
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	return s.next.RoundTrip(r)
}

func slowUpstreams(delay time.Duration) func(*proxyServer, *Socks5Options, *socks5Server) {
	return func(ps *proxyServer, _ *Socks5Options, _ *socks5Server) {
		ps.socks5AllowPrivate = true
		ps.transport = slowTransport{next: ps.transport, delay: delay}
		ps.guardedTransport = slowTransport{next: ps.guardedTransport, delay: delay}
	}
}

// plainUpstream serves plain HTTP, for the tunnels that carry http:// requests.
func plainUpstream(t *testing.T) (*httptest.Server, uint16) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain reply "+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	return srv, uint16(n)
}

// connectHTTPDoor opens a CONNECT tunnel through the HTTP door and returns the raw TCP connection.
func connectHTTPDoor(t *testing.T, ps *proxyServer, target string) *net.TCPConn {
	t.Helper()
	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)
	raw, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername + ":" + testSocks5Token))
	if _, err := io.WriteString(raw, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: %v %v", resp, err)
	}
	return raw.(*net.TCPConn)
}

// sendThenHalfClose writes one request, shuts the sending side, and reads the reply.
func sendThenHalfClose(t *testing.T, conn net.Conn, closeWrite func() error, host string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://"+host+"/half", nil)
	req.Close = true
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	if err := closeWrite(); err != nil {
		t.Fatalf("half-close: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("no reply after the half-close: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestTunnelRepliesAfterTheClientHalfCloses(t *testing.T) {
	t.Run("HTTP door, plain HTTP, TCP FIN", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, slowUpstreams(300*time.Millisecond))
		_, port := plainUpstream(t)
		target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		conn := connectHTTPDoor(t, f.ps, target)
		status, body := sendThenHalfClose(t, conn, conn.CloseWrite, target)
		if status != http.StatusOK || body != "plain reply /half" {
			t.Fatalf("status=%d body=%q", status, body)
		}
	})

	t.Run("HTTP door, HTTPS, TLS close_notify", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, slowUpstreams(300*time.Millisecond))
		target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.upstreamPort(t))))
		raw := connectHTTPDoor(t, f.ps, target)
		inner := tls.Client(raw, &tls.Config{RootCAs: f.proxyCAs, ServerName: "127.0.0.1"})
		status, _ := sendThenHalfClose(t, inner, inner.CloseWrite, target)
		if status != http.StatusOK {
			t.Fatalf("status=%d", status)
		}
	})

	t.Run("SOCKS5 door, HTTPS, TLS close_notify", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, slowUpstreams(300*time.Millisecond))
		conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", f.upstreamPort(t))
		if conn == nil {
			t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
		}
		defer conn.Close()
		inner := tls.Client(conn, &tls.Config{RootCAs: f.proxyCAs, ServerName: "127.0.0.1"})
		status, _ := sendThenHalfClose(t, inner, inner.CloseWrite, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.upstreamPort(t)))))
		if status != http.StatusOK {
			t.Fatalf("status=%d", status)
		}
	})

	// What E2B does with a sandbox's plain HTTP request: the sandbox's FIN becomes a close_notify on the
	// outer TLS connection to the SOCKS5 port.
	t.Run("SOCKS5 door, plain HTTP, outer TLS close_notify", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, slowUpstreams(300*time.Millisecond))
		_, port := plainUpstream(t)
		conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", port)
		if conn == nil {
			t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
		}
		defer conn.Close()
		outer := conn.(*tls.Conn)
		status, body := sendThenHalfClose(t, outer, outer.CloseWrite, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if status != http.StatusOK || body != "plain reply /half" {
			t.Fatalf("status=%d body=%q", status, body)
		}
	})
}

func TestTunnelEndsWhenTheClientLeavesForGood(t *testing.T) {
	t.Run("mid request", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, slowUpstreams(300*time.Millisecond))
		_, port := plainUpstream(t)
		conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", port)
		if conn == nil {
			t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
		}
		req, _ := http.NewRequest(http.MethodGet, "http://example.test/gone", nil)
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		waitForConnections(t, f.server, 5*time.Second)
	})

	t.Run("before any request", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, slowUpstreams(300*time.Millisecond))
		_, port := plainUpstream(t)
		conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", port)
		if conn == nil {
			t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
		}
		// Enough to pass the SOCKS5 door's HTTP check and reach the tunnel's server, but not a whole request.
		_, _ = conn.Write([]byte("GET /partial HTTP/1.1\r\n"))
		_ = conn.Close()
		// The header timeout is 10s; a connection that left before sending a request must not wait for it.
		waitForConnections(t, f.server, 2*time.Second)
	})
}

func TestTunnelKeepsTheConnectionAliveBetweenRequests(t *testing.T) {
	f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, slowUpstreams(0))
	_, port := plainUpstream(t)
	conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", port)
	if conn == nil {
		t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://example.test/n"+strconv.Itoa(i), nil)
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasSuffix(string(body), "/n"+strconv.Itoa(i)) {
			t.Fatalf("request %d: status=%d body=%q", i, resp.StatusCode, body)
		}
	}
}

func waitForConnections(t *testing.T, s *socks5Server, within time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { s.wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatalf("the connection was still being handled after %s", within)
	}
}

// halfClosedPipe returns the server end of a pipe whose client end has already shut its sending side.
func halfClosedPipe(t *testing.T, inRequest bool) *halfCloseConn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	_ = client.Close()
	c := newHalfCloseConn(server)
	c.setInRequest(inRequest)
	return c
}

func TestHalfCloseConnPassesTheEndThroughOutsideARequest(t *testing.T) {
	c := halfClosedPipe(t, false)
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

func TestHalfCloseConnWaitsForTheDeadline(t *testing.T) {
	c := halfClosedPipe(t, true)
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	start := time.Now()
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline error", err)
	}
	if waited := time.Since(start); waited < 100*time.Millisecond {
		t.Fatalf("returned after %s, before the deadline", waited)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatal("net/http needs the deadline error to report Timeout()")
	}
}

// net/http ends its background read by moving the deadline into the past while the read is already waiting.
func TestHalfCloseConnWakesWhenTheDeadlineMovesToThePast(t *testing.T) {
	c := halfClosedPipe(t, true)
	_ = c.SetReadDeadline(time.Time{})
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = c.SetReadDeadline(time.Unix(1, 0))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("err = %v, want a deadline error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting read ignored a deadline in the past")
	}
}

func TestHalfCloseConnWakesOnClose(t *testing.T) {
	c := halfClosedPipe(t, true)
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = c.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("a read after Close returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting read ignored Close")
	}
}

// A client that left looks the same as one that only stopped sending, so an upstream that never answers must not
// hold the tunnel open for good.
func TestHalfCloseConnGivesUpAfterTheReplyLimit(t *testing.T) {
	c := halfClosedPipe(t, true)
	c.replyLimit = 150 * time.Millisecond
	start := time.Now()
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF once the reply limit passes", err)
	}
	if waited := time.Since(start); waited < 100*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("gave up after %s, want about the 150ms limit", waited)
	}
}
