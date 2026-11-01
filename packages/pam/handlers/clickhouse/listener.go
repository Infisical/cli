package clickhouse

import (
	"errors"
	"net"
	"net/http"
	"sync"
)

type singleConnListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	listener := &singleConnListener{conns: make(chan net.Conn, 1), closed: make(chan struct{})}
	listener.conns <- &closeNotifyConn{Conn: conn, onClose: listener.Close}
	return listener
}

type closeNotifyConn struct {
	net.Conn
	onClose func() error
	once    sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { _ = c.onClose() })
	return err
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func isListenerDone(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed)
}
