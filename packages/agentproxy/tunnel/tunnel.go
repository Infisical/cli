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
	"os"
	"sync"
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

	// A stream has no socket of its own, so read deadlines are implemented here rather than delegated. They
	// are not optional: net/http's hijack path (abortPendingRead) sets the read deadline in the past and then
	// blocks until the in-flight read returns, so a no-op deadline deadlocks every CONNECT the moment an
	// agent asks for an HTTPS host. Reads therefore run on their own goroutine and Read waits with a timer.
	readOnce     sync.Once
	reads        chan readChunk
	leftover     []byte
	readErr      error
	deadlineMu   sync.Mutex
	readDeadline time.Time
	// Closed and replaced on every SetReadDeadline, so a read already blocked with no deadline still learns
	// that one has appeared. Without it the hijack path sets a deadline nothing is listening for.
	deadlineChanged chan struct{}
}

type readChunk struct {
	data []byte
	err  error
}

// The reader goroutine owns the underlying body and hands whole chunks over, so a read abandoned on a
// deadline loses nothing: the chunk waits in the channel for the next Read.
func (c *streamConn) startReader() {
	c.reads = make(chan readChunk, 1)
	go func() {
		for {
			buf := make([]byte, 32*1024)
			n, err := c.reader.Read(buf)
			if n > 0 {
				c.reads <- readChunk{data: buf[:n]}
			}
			if err != nil {
				c.reads <- readChunk{err: err}
				return
			}
		}
	}()
}

// The deadline and the channel that announces a change to it, read together so a waiter cannot miss an
// update between the two.
func (c *streamConn) deadlineState() (time.Time, chan struct{}) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.deadlineChanged == nil {
		c.deadlineChanged = make(chan struct{})
	}
	return c.readDeadline, c.deadlineChanged
}

func (c *streamConn) Read(b []byte) (int, error) {
	c.readOnce.Do(c.startReader)

	if len(c.leftover) > 0 {
		n := copy(b, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}

	for {
		deadline, changed := c.deadlineState()

		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}

		select {
		case chunk := <-c.reads:
			if timer != nil {
				timer.Stop()
			}
			if len(chunk.data) > 0 {
				n := copy(b, chunk.data)
				c.leftover = chunk.data[n:]
				return n, nil
			}
			c.readErr = chunk.err
			return 0, chunk.err
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
			// A deadline arrived, moved, or was cleared. Re-arm against the new one.
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

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

func (c *streamConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	if c.deadlineChanged != nil {
		close(c.deadlineChanged)
	}
	c.deadlineChanged = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

// Writes go into the HTTP/2 flow-control window rather than to a socket, and nothing in the forwarding path
// relies on interrupting one, so a write deadline is accepted and ignored.
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
