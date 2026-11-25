package pam

import (
	"context"
	"net"

	"github.com/go-resty/resty/v2"
)

// NewLoopbackTransport builds the transport half of a proxy that lives inside a longer-running
// process, such as one serving a single command. It never exits the process on shutdown.
//
// The transport runs on a child of ctx so it has a cancel of its own: BaseProxyServer calls cancel
// unconditionally, and a nil one would turn a dropped gateway into a panic.
func NewLoopbackTransport(ctx context.Context, httpClient *resty.Client, resourceType string, provider SessionProvider) *BaseProxyServer {
	ctx, cancel := context.WithCancel(ctx)
	return &BaseProxyServer{
		httpClient:       httpClient,
		resourceType:     resourceType,
		provider:         provider,
		ctx:              ctx,
		cancel:           cancel,
		shutdownCh:       make(chan struct{}),
		keepProcessAlive: true,
	}
}

// DialRelay opens the relay leg of a connection using an already-resolved session.
func (b *BaseProxyServer) DialRelay(session LiveSession) (net.Conn, error) {
	return b.createRelayConnectionWith(session)
}

// DialGateway performs the gateway mTLS handshake over relayConn.
//
// Callers pass the same session they dialed the relay with. The handshake presents that session's
// certificates, and they have to match the relay stream they travel over.
func (b *BaseProxyServer) DialGateway(relayConn net.Conn, alpn ALPN, session LiveSession) (net.Conn, error) {
	return b.createGatewayConnectionWith(relayConn, alpn, session)
}
