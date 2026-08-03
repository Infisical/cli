package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// gatewayResourceType maps an account type to the resource type the gateway advertises for it.
//
// The gateway reports brokering protocols rather than account types, so a Windows AD account is
// served under "windows" and never appears as "windows-ad" in its capabilities. Validating the raw
// account type would reject a perfectly current gateway. startRDPProxy in packages/pam/local
// hardcodes the same translation for the interactive flow, where the account type is known to be
// one of those two.
func gatewayResourceType(accountType string) string {
	if accountType == pam.AccountTypeWindowsAd {
		return pam.AccountTypeWindows
	}
	return accountType
}

// AgentProxy is a loopback TCP relay whose PAM session is created on first connection. Every
// port-based account type uses it, since the client side of all of them is the same raw relay.
//
// It owns its own lifecycle rather than borrowing the interactive proxies': those exit the process
// on shutdown, which would kill the agent this one was launched for.
type AgentProxy struct {
	// transport dials the relay and gateway, and knows how to end a session.
	transport *pam.BaseProxyServer

	path     string
	provider *LazySessionProvider
	server   net.Listener
	port     int

	// gatewayClosePerRequest marks account types where the gateway closing its side of a connection
	// is how a normal request ends, rather than a sign that the session is gone.
	gatewayClosePerRequest bool

	ctx               context.Context
	cancel            context.CancelFunc
	shutdownCh        chan struct{}
	shutdownOnce      sync.Once
	activeConnections sync.WaitGroup

	validateOnce sync.Once
	validateErr  error

	errMu   sync.Mutex
	lastErr error
}

func NewAgentProxy(httpClient *resty.Client, path, accountType string, provider *LazySessionProvider) *AgentProxy {
	ctx, cancel := context.WithCancel(context.Background())

	proxy := &AgentProxy{
		transport: pam.NewAgentTransport(ctx, httpClient, gatewayResourceType(accountType), provider),
		path:      path,
		provider:  provider,
		// A kubernetes client opens one connection per command, and the gateway closes its side once
		// the request is answered. Treating that as session death would discard a perfectly good
		// session after every kubectl invocation. KubernetesProxyServer.handleConnection in
		// packages/pam/local makes the same distinction.
		gatewayClosePerRequest: accountType == pam.AccountTypeKubernetes,
		ctx:                    ctx,
		cancel:                 cancel,
		shutdownCh:             make(chan struct{}),
	}
	// The provider decides when a session is finished with; the transport knows how to end one.
	provider.SetTerminator(proxy.transport.TerminateSession)
	return proxy
}

// Start binds the loopback listener. No PAM session is created here.
func (p *AgentProxy) Start(port int) error {
	var err error
	if port == 0 {
		p.server, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		p.server, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	}
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	p.port = p.server.Addr().(*net.TCPAddr).Port
	return nil
}

func (p *AgentProxy) Port() int {
	return p.port
}

// LastError reports the most recent connection failure, for the teardown summary.
func (p *AgentProxy) LastError() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.lastErr
}

func (p *AgentProxy) recordError(err error) {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	p.lastErr = err
}

// Run accepts connections until shutdown. Unlike the single-session proxies there is no overall
// expiry check here: session expiry is handled per session by the provider, which mints a fresh
// one on the next connection.
func (p *AgentProxy) Run() {
	defer p.server.Close()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.shutdownCh:
			return
		default:
			if tcpListener, ok := p.server.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}

			conn, err := p.server.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				select {
				case <-p.ctx.Done():
					return
				case <-p.shutdownCh:
					return
				default:
					log.Error().Err(err).Str("account", p.path).Msg("Failed to accept connection")
					continue
				}
			}

			p.activeConnections.Add(1)
			go p.handleConnection(conn)
		}
	}
}

// Shutdown ends any session this proxy created and stops the listener. It never exits the process.
func (p *AgentProxy) Shutdown() {
	p.shutdownOnce.Do(func() {
		// Closing the provider first is what makes shutdown final: a connection accepted while we
		// tear down can no longer create a session after we have stopped looking for ones to end.
		p.provider.Close()

		close(p.shutdownCh)

		if p.server != nil {
			p.server.Close()
		}

		p.cancel()

		// Live connections release their session as they finish, and the last release ends it.
		// Drain then ends whatever a connection that outstayed the wait is still holding.
		p.waitForConnections(5 * time.Second)
		p.provider.Drain(5 * time.Second)

		log.Debug().Str("account", p.path).Msg("Agent proxy shutdown complete")
	})
}

// waitForConnections waits for in-flight connections to finish, giving up after timeout.
func (p *AgentProxy) waitForConnections(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		p.activeConnections.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		log.Warn().Str("account", p.path).Msg("Timed out waiting for connections to close")
	}
}

// validateGatewaySupport checks the gateway advertises this account type, once per proxy. It runs
// after a session exists, since fetching capabilities needs the session's certificates.
// The result is remembered rather than recomputed, so an unsupported type keeps failing
// every connection instead of silently passing after the first attempt.
func (p *AgentProxy) validateGatewaySupport() error {
	p.validateOnce.Do(func() {
		p.validateErr = p.transport.ValidateResourceTypeSupported()
	})
	return p.validateErr
}

func (p *AgentProxy) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.activeConnections.Done()
	}()

	select {
	case <-p.ctx.Done():
		return
	default:
	}

	log.Debug().Str("account", p.path).Msgf("New connection from %s", clientConn.RemoteAddr())

	// This is where a session is born. Everything before now was just a bound socket.
	//
	// Both hops are dialed with this one resolved session. Resolving again for the gateway hop
	// would let a session created in between be used for the handshake, presenting certificates
	// the relay stream underneath was never opened with.
	session, release, err := p.provider.Acquire(p.ctx)
	if err != nil {
		if errors.Is(err, ErrSessionProviderClosed) || errors.Is(err, context.Canceled) {
			log.Debug().Str("account", p.path).Msg("Connection accepted during shutdown, not creating a session")
			return
		}
		p.recordError(err)
		log.Error().Err(err).Str("account", p.path).Msg("Failed to create PAM session")
		return
	}
	defer release()

	// A failure here may mean this session is dead: the API caps duration at the account's maximum,
	// so a manifest asking for longer than allowed leaves us holding a session the server has
	// already ended. Discard it so the next connection creates a fresh one, and so that a session
	// which is somehow still live gets terminated instead of lingering.
	relayConn, err := p.transport.DialRelay(session)
	if err != nil {
		p.recordError(err)
		p.provider.Discard(session)
		log.Error().Err(err).Str("account", p.path).Msg("Failed to connect to relay")
		return
	}
	defer relayConn.Close()

	if err := p.validateGatewaySupport(); err != nil {
		p.recordError(err)
		log.Error().Err(err).Str("account", p.path).Msg("Gateway does not support this account type")
		return
	}

	gatewayConn, err := p.transport.DialGateway(relayConn, pam.ALPNInfisicalPAMProxy, session)
	if err != nil {
		p.recordError(err)
		p.provider.Discard(session)
		log.Error().Err(err).Str("account", p.path).Msg("Failed to connect to gateway")
		return
	}
	defer gatewayConn.Close()

	connCtx, connCancel := context.WithCancel(p.ctx)
	defer connCancel()

	gatewayErrCh := make(chan error, 1)
	clientErrCh := make(chan error, 1)

	go func() {
		defer connCancel()
		_, err := io.Copy(clientConn, gatewayConn)
		gatewayErrCh <- err
	}()

	go func() {
		defer connCancel()
		_, err := io.Copy(gatewayConn, clientConn)
		clientErrCh <- err
	}()

	// For a persistent protocol a gateway-side disconnect means the session is gone (expired, or
	// terminated from the dashboard). Unlike a single-session proxy we don't shut down: we discard
	// the session so the agent's next connection transparently gets a new one.
	//
	// Where the gateway closes once per request, that same signal is just the end of the request,
	// and discarding on it would create a session per command.
	select {
	case <-gatewayErrCh:
		if p.gatewayClosePerRequest {
			log.Debug().Str("account", p.path).Msg("Gateway closed after request, keeping session")
		} else {
			log.Debug().Str("account", p.path).Msg("Gateway disconnected, discarding session")
			p.provider.Discard(session)
		}
	case <-clientErrCh:
	case <-connCtx.Done():
	}

	log.Debug().Str("account", p.path).Msgf("Connection closed for %s", clientConn.RemoteAddr())
}
