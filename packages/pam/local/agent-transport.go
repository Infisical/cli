package pam

import (
	"context"
	"net"

	"github.com/go-resty/resty/v2"
)

// This file is the whole surface the agent runner (packages/pam/agent) uses to reach the PAM
// transport. Proxies for agents live in that package, next to the rest of the agent code, rather
// than here among the interactive `pam access` proxies; what they still need from here is the relay
// and gateway dialing every proxy shares, which is unexported because BaseProxyServer owns it.
//
// Nothing in the interactive flow calls anything below.

// NewAgentTransport builds the transport half of a proxy whose PAM session is created on demand.
//
// resourceType is what gets compared against the gateway's advertised capabilities, and provider
// resolves the session behind each dial. ctx belongs to the caller, which owns its own shutdown:
// unlike the interactive proxies, an agent's proxy ending must not take the process with it.
func NewAgentTransport(ctx context.Context, httpClient *resty.Client, resourceType string, provider SessionProvider) *BaseProxyServer {
	return &BaseProxyServer{
		httpClient:   httpClient,
		resourceType: resourceType,
		provider:     provider,
		ctx:          ctx,
		shutdownCh:   make(chan struct{}),
		// Belt and braces: nothing here reaches gracefulShutdown, but if it ever did, one account's
		// proxy exiting the whole process would take the agent down with it.
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
// certificates, so resolving a session again here could hand the gateway credentials that don't
// belong to the relay stream underneath.
func (b *BaseProxyServer) DialGateway(relayConn net.Conn, alpn ALPN, session LiveSession) (net.Conn, error) {
	return b.createGatewayConnectionWith(relayConn, alpn, session)
}
