package oracle

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type OracleProxyConfig struct {
	TargetAddr     string
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

func (p *OracleProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	return p.handleConnectionProxied(ctx, clientConn)
}

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
