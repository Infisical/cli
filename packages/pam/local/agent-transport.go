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
func NewAgentTransport(ctx context.Context, httpClient *resty.Client, resourceType string, provider SessionProvider) *BaseProxyServer {
	return &BaseProxyServer{
		httpClient:   httpClient,
		resourceType: resourceType,
		provider:     provider,
		ctx:          ctx,
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
