package agentvault

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// The proxy's HTTP port serves two kinds of client. Agents speak plain HTTP to it, as their HTTPS_PROXY says:
// their clients (curl, Codex's WebSocket) can't trust a proxy that speaks TLS itself. `infisical agent-vault
// connect` speaks TLS to it, because a database tunnel carries the session token and the database's own protocol in
// the clear. The first byte tells them apart: a TLS handshake record starts with 0x16, and no HTTP request does.
type doorListener struct {
	inner       net.Listener
	tlsConfig   *tls.Config
	peekTimeout time.Duration

	conns chan net.Conn
	errs  chan error
	done  chan struct{}
	once  sync.Once
}

func newDoorListener(inner net.Listener, tlsConfig *tls.Config, peekTimeout time.Duration) *doorListener {
	d := &doorListener{
		inner:       inner,
		tlsConfig:   tlsConfig,
		peekTimeout: peekTimeout,
		conns:       make(chan net.Conn),
		errs:        make(chan error, 1),
		done:        make(chan struct{}),
	}
	go d.acceptLoop()
	return d
}

// The TLS door's certificate, minted per handshake so the 24-hour leaf is replaced before it expires. The name is
// fixed: an unauthenticated client must not choose what gets minted.
func proxyDoorTLSConfig(ca *caManager) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// HTTP/2 has no CONNECT hijack, which the database tunnel needs.
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			leaf, err := ca.mintLeaf(ProxyTLSServerName)
			if err != nil {
				return nil, err
			}
			return &leaf, nil
		},
	}
}

func (d *doorListener) acceptLoop() {
	for {
		conn, err := d.inner.Accept()
		if err != nil {
			select {
			case d.errs <- err:
			case <-d.done:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
		// One goroutine per connection, so a client that connects and says nothing never holds up the others.
		go d.classify(conn)
	}
}

func (d *doorListener) classify(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(d.peekTimeout))
	buffered := newBufferedConn(conn)
	first, err := buffered.reader.Peek(1)
	// Cleared, or a long database connection would be cut once the peek's deadline passed.
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}

	var out net.Conn = buffered
	if first[0] == tlsRecordTypeHandshake {
		// Handed over bare, so net/http does the handshake, sets r.TLS and can still hijack the connection.
		out = tls.Server(buffered, d.tlsConfig)
	}
	select {
	case d.conns <- out:
	case <-d.done:
		_ = out.Close()
	}
}

func (d *doorListener) Accept() (net.Conn, error) {
	select {
	case conn := <-d.conns:
		return conn, nil
	case err := <-d.errs:
		return nil, err
	case <-d.done:
		return nil, net.ErrClosed
	}
}

func (d *doorListener) Close() error {
	d.once.Do(func() { close(d.done) })
	return d.inner.Close()
}

func (d *doorListener) Addr() net.Addr { return d.inner.Addr() }
