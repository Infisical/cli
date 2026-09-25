package clickhouse

import (
	"bufio"
	"net"
	"time"
)

// Which protocol a client speaks is decided by its driver, not the user, so one port serves both. A native
// session opens with the Hello code, a uvarint 0; every HTTP request opens with an ASCII method letter.
const nativeHelloByte = 0x00

// The peek happens before any HTTP server exists, so ReadHeaderTimeout does not cover it.
const sniffTimeout = 30 * time.Second

type peekConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Embedding the net.Conn interface hides this, and net/http uses it to half-close rather than reset.
func (c *peekConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Returns a connection that still replays the byte it read to decide.
func sniffProtocol(conn net.Conn) (net.Conn, bool, error) {
	reader := bufio.NewReaderSize(conn, 64<<10)

	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	first, err := reader.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return conn, false, err
	}

	return &peekConn{Conn: conn, reader: reader}, first[0] == nativeHelloByte, nil
}
