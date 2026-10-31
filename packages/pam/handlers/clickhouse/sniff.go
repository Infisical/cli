package clickhouse

import (
	"bufio"
	"net"
	"time"
)

// Native opens with a uvarint 0; HTTP with an ASCII method letter.
const nativeHelloByte = 0x00

var sniffTimeout = 30 * time.Second

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

func sniffProtocol(conn net.Conn) (net.Conn, bool, error) {
	reader := bufio.NewReaderSize(conn, 64<<10)

	// No HTTP server exists yet, so ReadHeaderTimeout covers none of this, and a relayed session
	// ignores a read deadline.
	idle := newIdleTimer(sniffTimeout, conn)
	idle.reset()
	defer idle.stop()

	first, err := reader.Peek(1)
	if err != nil {
		return conn, false, err
	}

	return &peekConn{Conn: conn, reader: reader}, first[0] == nativeHelloByte, nil
}
