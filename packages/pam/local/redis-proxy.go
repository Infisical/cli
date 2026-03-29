package pam

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type RedisProxyServer struct {
	BaseProxyServer // Embed common functionality
	server          net.Listener
	port            int
}

func StartRedisLocalProxy(accessToken string, accessParams PAMAccessParams, projectID string, durationStr string, port int) {
	log.Info().Msgf("Starting Redis proxy for account: %s", accessParams.GetDisplayName())
	log.Info().Msgf("Session duration: %s", durationStr)

	httpClient := resty.New()
	httpClient.SetAuthToken(accessToken)
	httpClient.SetHeader("User-Agent", "infisical-cli")

	pamRequest := accessParams.ToAPIRequest(projectID, durationStr)

	pamResponse, err := CallPAMAccessWithMFA(httpClient, pamRequest)
	if err != nil {
		if HandleApprovalWorkflow(httpClient, err, projectID, accessParams, durationStr) {
			return
		}
		util.HandleError(err, "Failed to access PAM account")
		return
	}

	// Verify this is a Redis resource
	if pamResponse.ResourceType != session.ResourceTypeRedis {
		util.HandleError(fmt.Errorf("account is not a Redis resource, got: %s", pamResponse.ResourceType), "Invalid resource type")
		return
	}

	log.Info().Msgf("Redis session created with ID: %s", pamResponse.SessionId)

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &RedisProxyServer{
		BaseProxyServer: BaseProxyServer{
			httpClient:             httpClient,
			relayHost:              pamResponse.RelayHost,
			relayClientCert:        pamResponse.RelayClientCertificate,
			relayClientKey:         pamResponse.RelayClientPrivateKey,
			relayServerCertChain:   pamResponse.RelayServerCertificateChain,
			gatewayClientCert:      pamResponse.GatewayClientCertificate,
			gatewayClientKey:       pamResponse.GatewayClientPrivateKey,
			gatewayServerCertChain: pamResponse.GatewayServerCertificateChain,
			sessionExpiry:          time.Now().Add(duration),
			sessionId:              pamResponse.SessionId,
			resourceType:           pamResponse.ResourceType,
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
		},
	}

	if err := proxy.ValidateResourceTypeSupported(); err != nil {
		util.HandleError(err, "Gateway version outdated")
		return
	}

	err = proxy.Start(port)
	if err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	if port == 0 {
		util.PrintfStderr("Redis proxy started for account %s with duration %s on port %d (auto-assigned)\n", accessParams.GetDisplayName(), duration.String(), proxy.port)
	} else {
		util.PrintfStderr("Redis proxy started for account %s with duration %s on port %d\n", accessParams.GetDisplayName(), duration.String(), proxy.port)
	}

	username, ok := pamResponse.Metadata["username"]
	if !ok {
		username = "" // Redis may not always have username
	}

	log.Info().Msgf("Redis proxy server listening on port %d", proxy.port)
	util.PrintfStderr("\n")
	util.PrintfStderr("**********************************************************************\n")
	util.PrintfStderr("                  Redis Proxy Session Started!                  \n")
	util.PrintfStderr("----------------------------------------------------------------------\n")
	util.PrintfStderr("Resource: %s, Account: %s\n", accessParams.ResourceName, accessParams.AccountName)
	util.PrintfStderr("\n")
	util.PrintfStderr("You can now connect to your Redis instance using:\n")
	if username != "" {
		util.PrintfStderr("redis://%s@localhost:%d", username, proxy.port)
	} else {
		util.PrintfStderr("redis://localhost:%d", proxy.port)
	}
	util.PrintfStderr("\n**********************************************************************\n")
	util.PrintfStderr("\n")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func (p *RedisProxyServer) Start(port int) error {
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

func (p *RedisProxyServer) gracefulShutdown() {
	p.shutdownOnce.Do(func() {
		log.Info().Msg("Starting graceful shutdown of Redis proxy...")

		// Send session termination notification before cancelling context
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

		log.Info().Msg("Redis proxy shutdown complete")
		os.Exit(0)
	})
}

func (p *RedisProxyServer) Run() {
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
			// Check if session has expired
			if time.Now().After(p.sessionExpiry) {
				log.Warn().Msg("Redis session expired, shutting down proxy")
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

func (p *RedisProxyServer) handleConnection(clientConn net.Conn) {
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

	log.Info().Msg("Established connection to Redis resource")

	connCtx, connCancel := context.WithCancel(p.ctx)
	defer connCancel()

	errCh := make(chan error, 2)

	// Bidirectional data forwarding with context cancellation
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
		errCh <- err
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
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err != nil {
			p.HandleGatewayDisconnect()
		}
	case <-connCtx.Done():
		log.Info().Msg("Connection cancelled by context")
	}

	log.Info().Msgf("Connection closed for client: %s", clientConn.RemoteAddr().String())
}
