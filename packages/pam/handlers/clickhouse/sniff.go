package clickhouse

import (
	"bufio"
	"net"
	"time"
)

// ClickHouse serves two interfaces on two ports, and which one a client speaks depends on the driver rather than
// on anything the user chose: clickhouse-client is native-only, the JDBC driver is HTTP-only. A session hands out
// one local port and reads the first byte to tell them apart, so nobody has to pick a protocol.
//
// A native session opens with the Hello packet code, a uvarint 0. Every HTTP request opens with the ASCII letter
// of its method, so the two can never be confused.
const nativeHelloByte = 0x00

// A client that connects and then says nothing would otherwise park the session handler forever: the peek
// happens before any HTTP server exists, so ReadHeaderTimeout does not cover it.
const sniffTimeout = 30 * time.Second

// peekConn replays the sniffed byte to whichever handler takes the connection.
type peekConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// CloseWrite is promoted explicitly: embedding the net.Conn interface hides it, and net/http uses it to
// half-close rather than resetting a connection it is finished with.
func (c *peekConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// sniffProtocol reports whether the client opened a native session, and returns a connection that still replays
// the byte it read to decide.
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
