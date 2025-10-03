package pam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type ProxyServer struct {
	server                 net.Listener
	port                   int
	relayHost              string
	relayClientCert        string
	relayClientKey         string
	relayServerCertChain   string
	gatewayClientCert      string
	gatewayClientKey       string
	gatewayServerCertChain string
	sessionExpiry          time.Time
	sessionId              string
	ctx                    context.Context
	cancel                 context.CancelFunc
	activeConnections      sync.WaitGroup
	shutdownOnce           sync.Once
	shutdownCh             chan struct{}
}

type ALPN string

const (
	ALPNInfisicalPAMProxy        ALPN = "infisical-pam-proxy"
	ALPNInfisicalPAMCancellation ALPN = "infisical-pam-session-cancellation"
)

func StartLocalProxy(accessToken string, accountID string, durationStr string, port int) {
	log.Info().Msgf("Starting PAM proxy for account ID: %s", accountID)
	log.Info().Msgf("Session duration: %s", durationStr)

	httpClient := resty.New()
	httpClient.SetAuthToken(accessToken)
	httpClient.SetHeader("User-Agent", "infisical-cli")

	pamRequest := api.PAMAccessRequest{
		Duration:  durationStr,
		AccountId: accountID,
	}

	pamResponse, err := api.CallPAMAccess(httpClient, pamRequest)
	if err != nil {
		util.HandleError(err, "Failed to access PAM account")
		return
	}

	log.Info().Msgf("PAM session created with ID: %s", pamResponse.SessionId)

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &ProxyServer{
		relayHost:              pamResponse.RelayHost,
		relayClientCert:        pamResponse.RelayClientCertificate,
		relayClientKey:         pamResponse.RelayClientPrivateKey,
		relayServerCertChain:   pamResponse.RelayServerCertificateChain,
		gatewayClientCert:      pamResponse.GatewayClientCertificate,
		gatewayClientKey:       pamResponse.GatewayClientPrivateKey,
		gatewayServerCertChain: pamResponse.GatewayServerCertificateChain,
		sessionExpiry:          time.Now().Add(duration),
		sessionId:              pamResponse.SessionId,
		ctx:                    ctx,
		cancel:                 cancel,
		shutdownCh:             make(chan struct{}),
	}

	err = proxy.Start(port)
	if err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	if port == 0 {
		fmt.Printf("PAM proxy started for account %s with duration %s on port %d (auto-assigned)\n", accountID, duration.String(), proxy.port)
	} else {
		fmt.Printf("PAM proxy started for account %s with duration %s on port %d\n", accountID, duration.String(), proxy.port)
	}

	log.Info().Msgf("Proxy server listening on port %d", proxy.port)
	log.Info().Msgf("Connect to your PAM resource using: localhost:%d", proxy.port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func (p *ProxyServer) Start(port int) error {
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

func (p *ProxyServer) gracefulShutdown() {
	p.shutdownOnce.Do(func() {
		log.Info().Msg("Starting graceful shutdown of PAM proxy...")

		// Send session termination notification before cancelling context
		p.notifySessionTermination()

		// Signal the accept loop to stop
		close(p.shutdownCh)

		// Close the server to stop accepting new connections
		if p.server != nil {
			p.server.Close()
		}

		// Cancel context to signal all goroutines to stop
		p.cancel()

		done := make(chan struct{})
		go func() {
			p.activeConnections.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Info().Msg("All connections closed gracefully")
		case <-time.After(10 * time.Second):
			log.Warn().Msg("Timeout waiting for connections to close, forcing shutdown")
		}

		log.Info().Msg("PAM proxy shutdown complete")
		os.Exit(0)
	})
}

// notifySessionTermination sends a termination notification through the gateway
func (p *ProxyServer) notifySessionTermination() {
	log.Info().Msgf("Notifying session termination for session ID: %s", p.sessionId)

	relayConn, err := p.createRelayConnection()
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay for termination notification")
		return
	}
	defer relayConn.Close()

	gatewayConn, err := p.createGatewayConnection(relayConn, ALPNInfisicalPAMCancellation)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway for termination notification")
		return
	}
	defer gatewayConn.Close()
	log.Info().Msg("Session termination notification sent successfully")
}

func (p *ProxyServer) Run() {
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
				log.Warn().Msg("PAM session expired, shutting down proxy")
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

func (p *ProxyServer) handleConnection(clientConn net.Conn) {
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

	relayConn, err := p.createRelayConnection()
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to relay")
		return
	}
	defer relayConn.Close()

	gatewayConn, err := p.createGatewayConnection(relayConn, ALPNInfisicalPAMProxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to gateway")
		return
	}
	defer gatewayConn.Close()

	log.Info().Msg("Established connection to PAM resource")

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
	case <-errCh:
	case <-connCtx.Done():
		log.Info().Msg("Connection cancelled by context")
	}

	log.Info().Msgf("Connection closed for client: %s", clientConn.RemoteAddr().String())
}

func (p *ProxyServer) createRelayConnection() (net.Conn, error) {
	var host string
	var port int = 8443

	if strings.Contains(p.relayHost, ":") {
		var portStr string
		var err error
		host, portStr, err = net.SplitHostPort(p.relayHost)
		if err != nil {
			return nil, fmt.Errorf("invalid relay host format: %w", err)
		}
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port in relay host: %w", err)
		}
	} else {
		host = p.relayHost
	}

	// Load relay certificates
	cert, err := tls.X509KeyPair([]byte(p.relayClientCert), []byte(p.relayClientKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load relay client certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(p.relayServerCertChain)) {
		return nil, fmt.Errorf("failed to parse relay server certificate chain")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   host,
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}

	log.Debug().Msg("Relay TLS connection established")
	return conn, nil
}

func (p *ProxyServer) createGatewayConnection(relayConn net.Conn, alpn ALPN) (net.Conn, error) {
	// Load gateway certificates
	cert, err := tls.X509KeyPair([]byte(p.gatewayClientCert), []byte(p.gatewayClientKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load gateway client certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(p.gatewayServerCertChain)) {
		return nil, fmt.Errorf("failed to parse gateway server certificate chain")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{string(alpn)},
		ServerName:   "localhost",
	}

	gatewayConn := tls.Client(relayConn, tlsConfig)

	err = gatewayConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("failed to establish gateway mTLS: %w", err)
	}

	state := gatewayConn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, fmt.Errorf("gateway TLS handshake not complete")
	}

	log.Debug().Msg("Gateway mTLS connection established")
	return gatewayConn, nil
}
