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

type DatabaseProxyServer struct {
	BaseProxyServer
	server net.Listener
	port   int
}

type ALPN string

const (
	ALPNInfisicalPAMProxy        ALPN = "infisical-pam-proxy"
	ALPNInfisicalPAMCancellation ALPN = "infisical-pam-session-cancellation"
	ALPNInfisicalPAMCapabilities ALPN = "infisical-pam-capabilities"
)

func (p *DatabaseProxyServer) Start(port int) error {
	var err error
	if port == 0 {
		p.server, err = net.Listen("tcp", ":0")
	} else {
		p.server, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	}

	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	addr := p.server.Addr().(*net.TCPAddr)
	p.port = addr.Port

	return nil
}

func (p *DatabaseProxyServer) gracefulShutdown() {
	p.shutdownOnce.Do(func() {
		log.Info().Msg("Starting graceful shutdown of database proxy...")

		p.NotifySessionTermination()

		close(p.shutdownCh)

		if p.server != nil {
			p.server.Close()
		}

		p.cancel()

		p.WaitForConnectionsWithTimeout(10 * time.Second)

		log.Info().Msg("Database proxy shutdown complete")
		os.Exit(0)
	})
}

func (p *DatabaseProxyServer) Run() {
	defer p.server.Close()

	for {
		select {
		case <-p.ctx.Done():
			log.Info().Msg("Context cancelled, stopping proxy server")
			return
		case <-p.shutdownCh:
			log.Info().Msg("Shutdown signal received, stopping proxy server")
			return
		default:
			if time.Now().After(p.sessionExpiry) {
				log.Warn().Msg("Database session expired, shutting down proxy")
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

			p.activeConnections.Add(1)
			go p.handleConnection(conn)
		}
	}
}

func (p *DatabaseProxyServer) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.activeConnections.Done()
	}()

	log.Info().Msgf("New connection from %s", clientConn.RemoteAddr())

	select {
	case <-p.ctx.Done():
		log.Info().Msg("Context cancelled, closing connection immediately")
		return
	default:
	}

	relayConn, err := p.CreateRelayConnection()
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay")
		return
	}
	defer relayConn.Close()

	gatewayConn, err := p.CreateGatewayConnection(relayConn, ALPNInfisicalPAMProxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway")
		return
	}
	defer gatewayConn.Close()

	log.Info().Msg("Established connection to database resource")

	connCtx, connCancel := context.WithCancel(p.ctx)
	defer connCancel()

	gatewayErrCh, clientErrCh := p.NewDisconnectChannels()

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

	p.WaitForDisconnect(gatewayErrCh, clientErrCh, connCtx)

	log.Info().Msgf("Connection closed for client: %s", clientConn.RemoteAddr().String())
}
