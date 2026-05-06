package oracle

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

// OracleProxyConfig mirrors the shape used by other PAM database handlers so the
// dispatch in pam-proxy.go stays templatized. When EnableTLS is true, the
// upstream leg uses TLSConfig (built centrally in pam-proxy.go from the
// resource's sslRejectUnauthorized + sslCertificate fields).
type OracleProxyConfig struct {
	TargetAddr     string // "host:port"
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	SessionLogger  session.SessionLogger
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
