// Package tunnel multiplexes many independent byte streams over one already-encrypted connection.
//
// It exists because reaching a gateway is expensive: the relay opens a fresh SSH channel per client TCP
// connection, so a connection per CONNECT would cost three handshakes each, and agents open many short-lived
// tunnels to a handful of hosts. HTTP/2 gives per-stream flow control, cancellation that propagates, and
// full-duplex bodies (which SSE needs) without adding a dependency: x/net/http2 is already vendored.
//
// The transport carries no credentials and no authorization. Which session a connection belongs to is
// decided by the mTLS certificate it was established with, one layer below this.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

const (
	// Go's defaults (64 KiB per stream, 1 MiB per connection) throttle throughput badly for the payload
	// sizes agents move, so both windows are raised deliberately.
	maxUploadBufferPerStream     = 1 << 20
	maxUploadBufferPerConnection = 16 << 20
	maxReadFrameSize             = 64 << 10

	// Bounds how many tunnels one agent process may hold open at once, so a single session cannot exhaust
	// a gateway that is also serving PAM and other work.
	MaxConcurrentStreams = 64

	readIdleTimeout = 30 * time.Second
	pingTimeout     = 15 * time.Second
)

// streamConn adapts one HTTP/2 request/response body pair to net.Conn so the existing forward-proxy code can
// use it unchanged. Flushing on every write is what keeps a streamed response (SSE, in particular) arriving
// incrementally rather than in one buffered blob at the end.
type streamConn struct {
	reader io.Reader
	writer io.Writer
	closer func() error
	flush  func()
}

func (c *streamConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *streamConn) Write(b []byte) (int, error) {
	n, err := c.writer.Write(b)
	if c.flush != nil {
		c.flush()
	}
	return n, err
}

func (c *streamConn) Close() error {
	if c.closer != nil {
		return c.closer()
	}
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *streamConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// Deadlines are the underlying connection's business; a stream has none of its own.
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

// Client multiplexes outbound tunnels over one connection.
type Client struct {
	conn      net.Conn
	h2        *http2.ClientConn
	authority string
}

// NewClient takes ownership of conn, which must already be encrypted and authenticated.
func NewClient(conn net.Conn) (*Client, error) {
	// The client side exposes no upload-window knobs; those are server-side settings, and the gateway sets
	// them on its half. Keepalive matters more here: a relay hop can go quiet without closing, and a dead
	// mux has to be noticed rather than silently swallowing requests.
	transport := &http2.Transport{
		MaxReadFrameSize: maxReadFrameSize,
		ReadIdleTimeout:  readIdleTimeout,
		PingTimeout:      pingTimeout,
		AllowHTTP:        true,
	}

	h2, err := transport.NewClientConn(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to start tunnel multiplexer: %w", err)
	}

	return &Client{conn: conn, h2: h2, authority: "agent-gateway"}, nil
}

// Open starts one tunnel. The returned net.Conn is full-duplex: the request body carries bytes to the
// gateway and the response body carries them back.
func (c *Client) Open(ctx context.Context) (net.Conn, error) {
	pipeReader, pipeWriter := io.Pipe()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s/tunnel", c.authority), pipeReader)
	if err != nil {
		pipeWriter.Close()
		return nil, err
	}
	// Unknown length: this is a stream, not a payload.
	req.ContentLength = -1

	resp, err := c.h2.RoundTrip(req)
	if err != nil {
		pipeWriter.Close()
		return nil, fmt.Errorf("failed to open tunnel: %w", err)
	}

	return &streamConn{
		reader: resp.Body,
		writer: pipeWriter,
		closer: func() error {
			pipeWriter.Close()
			return resp.Body.Close()
		},
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// Serve accepts multiplexed tunnels on an already-encrypted server-side connection and hands each to
// handle as a net.Conn. reader must be the connection's buffered reader, because the HTTP/2 preface may
// already have been read into it during ALPN negotiation; passing conn directly loses those bytes.
func Serve(conn net.Conn, reader io.Reader, handle func(net.Conn)) error {
	server := &http2.Server{
		MaxConcurrentStreams:         MaxConcurrentStreams,
		MaxUploadBufferPerStream:     maxUploadBufferPerStream,
		MaxUploadBufferPerConnection: maxUploadBufferPerConnection,
		MaxReadFrameSize:             maxReadFrameSize,
		IdleTimeout:                  0,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		// Headers go out before any payload so the client's RoundTrip returns and it can start writing.
		w.WriteHeader(http.StatusOK)
		if flusher != nil {
			flusher.Flush()
		}

		stream := &streamConn{
			reader: r.Body,
			writer: w,
			flush: func() {
				if flusher != nil {
					flusher.Flush()
				}
			},
		}
		handle(stream)
	})

	server.ServeConn(&readerConn{Conn: conn, reader: reader}, &http2.ServeConnOpts{Handler: handler})
	return nil
}

// readerConn reads from a reader that may already hold buffered bytes, while writing to and closing the
// underlying connection.
type readerConn struct {
	net.Conn
	reader io.Reader
}

func (c *readerConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
