package pam

import (
	"context"
	"net"

	"github.com/go-resty/resty/v2"
)

// This file is the whole surface the agent runner (packages/pam/agent) uses to reach the PAM
// transport. It lives here because BaseProxyServer owns the relay and gateway dialing, and both its
// fields and those methods are unexported.
//
// Nothing in the interactive flow calls anything below.

// NewAgentTransport builds the transport half of a proxy whose PAM session is created on demand.
//
// resourceType is what gets compared against the gateway's advertised capabilities, and provider
// resolves the session behind each dial. ctx belongs to the caller, which owns its own shutdown,
// because an agent's proxy ending must leave the process running.
//
// The transport runs on a child of that context rather than on the context itself, so that it has a
// cancel of its own to give BaseProxyServer. Every other construction site sets one, and the methods
// there call it unconditionally; leaving it nil here would turn a dropped gateway into a panic.
// Shutdown still follows the caller, since cancelling a parent cancels the child, but a transport
// giving up on its own account now stops only itself. Handing it the caller's own cancel instead
// would let one account's dead gateway tear down every other account's proxy, and the agent with them.
func NewAgentTransport(ctx context.Context, httpClient *resty.Client, resourceType string, provider SessionProvider) *BaseProxyServer {
	ctx, cancel := context.WithCancel(ctx)
	return &BaseProxyServer{
		httpClient:   httpClient,
		resourceType: resourceType,
		provider:     provider,
		ctx:          ctx,
		cancel:       cancel,
		shutdownCh:   make(chan struct{}),
		// One account's proxy must never exit the process, which would take the agent down with it.
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
