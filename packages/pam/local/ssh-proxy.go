package pam

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

type SSHProxyServer struct {
	BaseProxyServer // Embed common functionality
	server          net.Listener
	port            int
}

func (p *SSHProxyServer) Start(port int) error {
	var err error
	if port == 0 {
		p.server, err = net.Listen("tcp", "127.0.0.1:0") // Bind to localhost only
	} else {
		p.server, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	}

	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	addr := p.server.Addr().(*net.TCPAddr)
	p.port = addr.Port

	log.Debug().Msgf("SSH proxy server listening on 127.0.0.1:%d", p.port)

	return nil
}

func (p *SSHProxyServer) gracefulShutdown() {
	p.shutdownOnce.Do(func() {
		log.Debug().Msg("Starting graceful shutdown of SSH proxy...")

		p.NotifySessionTermination()

		// Signal the accept loop to stop
		close(p.shutdownCh)

		// Close the server to stop accepting new connections
		if p.server != nil {
			p.server.Close()
		}

		// Cancel context to signal all goroutines to stop
		p.cancel()

		// Wait for connections to close
		p.WaitForConnectionsWithTimeout(10 * time.Second)

		log.Debug().Msg("SSH proxy shutdown complete")
		os.Exit(0)
	})
}

func (p *SSHProxyServer) Run() {
	defer p.server.Close()

	for {
		select {
		case <-p.ctx.Done():
			log.Debug().Msg("Context cancelled, stopping proxy server")
			return
		case <-p.shutdownCh:
			log.Debug().Msg("Shutdown signal received, stopping proxy server")
			return
		default:
			// Check if session has expired
			if time.Now().After(p.sessionExpiry) {
				log.Warn().Msg("SSH session expired, shutting down proxy")
				p.gracefulShutdown()
				return
			}

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
					log.Error().Err(err).Msg("Failed to accept connection")
					continue
				}
			}

			// Track active connection
			p.activeConnections.Add(1)
			go p.handleConnection(conn)
		}
	}
}

func (p *SSHProxyServer) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.activeConnections.Done()
	}()

	log.Debug().Msgf("New SSH connection from %s", clientConn.RemoteAddr())

	select {
	case <-p.ctx.Done():
		log.Debug().Msg("Context cancelled, closing connection immediately")
		return
	default:
	}

	// Connect to relay
	relayConn, err := p.CreateRelayConnection()
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay")
		return
	}
	defer relayConn.Close()

	// Connect to gateway (SSH proxy will handle the SSH protocol)
	gatewayConn, err := p.CreateGatewayConnection(relayConn, ALPNInfisicalPAMProxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway")
		return
	}
	defer gatewayConn.Close()

	log.Debug().Msg("Established connection to SSH gateway")

	connCtx, connCancel := context.WithCancel(p.ctx)
	defer connCancel()

	gatewayErrCh, clientErrCh := p.NewDisconnectChannels()

	// Client (local SSH) → Gateway (SSH proxy): if this side closes first, the client disconnected normally
	go func() {
		defer connCancel()
		_, err := io.Copy(gatewayConn, clientConn)
		if err != nil {
			select {
			case <-connCtx.Done():
			default:
				log.Debug().Err(err).Msg("Client to gateway copy ended")
			}
		}
		clientErrCh <- err
	}()

	// Gateway (SSH proxy) → Client (local SSH): if this side closes first, the gateway dropped the connection
	go func() {
		defer connCancel()
		_, err := io.Copy(clientConn, gatewayConn)
		if err != nil {
			select {
			case <-connCtx.Done():
			default:
				log.Debug().Err(err).Msg("Gateway to client copy ended")
			}
		}
		gatewayErrCh <- err
	}()

	p.WaitForDisconnect(gatewayErrCh, clientErrCh, connCtx)

	log.Debug().Msgf("SSH connection closed for client: %s", clientConn.RemoteAddr().String())
}
