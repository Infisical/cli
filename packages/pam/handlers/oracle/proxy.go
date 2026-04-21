package oracle

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

// prependedConn lets us push bytes we've already read back "in front" of a net.Conn's
// read stream, so downstream code can read them normally.
type prependedConn struct {
	net.Conn
	buf []byte
}

func (p *prependedConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// SetReadDeadline forwards to the wrapped conn; our prepended buf reads are synchronous
// so no deadline is needed for them.
func (p *prependedConn) SetReadDeadline(t time.Time) error {
	type withDeadline interface{ SetReadDeadline(time.Time) error }
	if d, ok := p.Conn.(withDeadline); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

// OracleProxyConfig mirrors the shape used by other PAM database handlers so the
// dispatch in pam-proxy.go stays templatized. Oracle-specific extras (the upstream
// TLS pinning fields) sit on top of the common eight.
type OracleProxyConfig struct {
	TargetAddr     string // "host:port"
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config // provided by dispatcher but not used on the upstream leg
	SessionID      string
	SessionLogger  session.SessionLogger

	SSLRejectUnauthorized bool
	SSLCertificate        string
}

type OracleProxy struct {
	config OracleProxyConfig
}

func NewOracleProxy(config OracleProxyConfig) *OracleProxy {
	return &OracleProxy{config: config}
}

// HandleConnection runs one end-to-end PAM session for a connecting Oracle client.
// The proxied-auth flow lives in handleConnectionProxied: pre-auth bytes are forwarded
// verbatim between client and upstream (so both negotiate with each other through us
// and end up in matching capability state), and we intercept only at the O5Logon
// boundary to swap placeholder-keyed material for real-password-keyed material.
func (p *OracleProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	return p.handleConnectionProxied(ctx, clientConn)
}


// detectConnectDataSupplement returns the length of a 16-bit-framed DATA packet at the
// start of buf, or 0 if buf doesn't look like one. Pattern: bytes[0:2] = length (16-bit
// BE, plausible 8..64K), bytes[2:4] = 0 (packet checksum), bytes[4] = 0x06 (DATA type).
func detectConnectDataSupplement(buf []byte) int {
	if len(buf) < 8 {
		return 0
	}
	length := int(buf[0])<<8 | int(buf[1])
	if length < 8 || length > 64*1024 {
		return 0
	}
	// Reject if the length field LOOKS like the high bytes of a 32-bit length
	// (i.e. bytes[2:4] are non-zero would imply a 32-bit length). A 16-bit framed
	// packet MUST have bytes[2:4] zero because that's the checksum field.
	if buf[2] != 0 || buf[3] != 0 {
		return 0
	}
	if buf[4] != 0x06 {
		return 0
	}
	return length
}

// relayWithTap copies src → dst byte-for-byte, Feed()'ing a copy of each read into the
// tap extractor. This is the hot path — it must not parse or log per-packet.
func relayWithTap(src, dst net.Conn, tap *QueryExtractor, errCh chan<- error) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				errCh <- werr
				return
			}
			tap.Feed(buf[:n])
		}
		if err != nil {
			errCh <- err
			return
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	return host, port, nil
}
