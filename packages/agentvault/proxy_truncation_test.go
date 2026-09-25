package agentvault

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type sessionOnlyResolver struct{}

func (sessionOnlyResolver) resolve(string) (*resolveResult, error) {
	return &resolveResult{SessionID: "s1"}, nil
}

// An upstream that announces a chunked body, sends one chunk, then drops the connection without the
// terminating chunk.
func newTruncatingUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Read(make([]byte, 4096))
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"))
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func newProxyForForwarding(t *testing.T) *httptest.Server {
	t.Helper()
	ps := &proxyServer{transport: newUpstreamTransport()}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(sessionOnlyResolver{}, ps.pollInterval)
	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)
	return front
}

// Returning normally after the status line is on the wire lets net/http close the chunked body off, so
// the agent is handed a well-formed 200 carrying half the data and no way to tell.
func TestAnUpstreamDyingMidBodyReachesTheAgentAsAFailure(t *testing.T) {
	upstream := newTruncatingUpstream(t)
	front := newProxyForForwarding(t)

	var logs bytes.Buffer
	restore := log.Logger
	log.Logger = zerolog.New(&logs)
	defer func() { log.Logger = restore }()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername+":agv_tok"))
	fmt.Fprintf(conn, "GET http://%s/thing HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", upstream, upstream, auth)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	defer resp.Body.Close()

	if _, readErr := io.ReadAll(resp.Body); readErr == nil {
		t.Fatal("the agent read the truncated body as a complete one")
	}
	// Close waits for the handler to return, so the log buffer is read after its last write, not during.
	front.Close()
	if !bytes.Contains(logs.Bytes(), []byte("upstream stream failed part way")) {
		t.Errorf("the upstream's failure should be logged, got %q", logs.String())
	}
}

// An agent that stops reading part way is its own business, so the abort happens without a line
// blaming the upstream for it. The standard library stays quiet about the same case.
func TestAnAgentHangingUpIsNotBlamedOnTheUpstream(t *testing.T) {
	// A slow upstream that keeps sending, so the agent's disconnect is what ends the copy.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Read(make([]byte, 4096))
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"))
				for i := 0; i < 20000; i++ {
					if _, err := c.Write([]byte("400\r\n" + string(make([]byte, 1024)) + "\r\n")); err != nil {
						return
					}
				}
			}()
		}
	}()

	front := newProxyForForwarding(t)

	var logs bytes.Buffer
	restore := log.Logger
	log.Logger = zerolog.New(&logs)
	defer func() { log.Logger = restore }()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername+":agv_tok"))
	fmt.Fprintf(conn, "GET http://%s/thing HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", ln.Addr(), ln.Addr(), auth)

	// Read a little, then hang up mid-stream.
	_, _ = io.ReadFull(bufio.NewReader(conn), make([]byte, 256))
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = conn.Close()

	// Close waits for the handler to notice the hang-up and unwind, so the buffer is read after its last write.
	front.Close()
	if bytes.Contains(logs.Bytes(), []byte("upstream stream failed part way")) {
		t.Errorf("the agent hanging up was reported as an upstream failure: %q", logs.String())
	}
}
