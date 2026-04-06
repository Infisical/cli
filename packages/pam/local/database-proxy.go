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

type DatabaseProxyServer struct {
	BaseProxyServer // Embed common functionality
	server          net.Listener
	port            int
}

type ALPN string

const (
	ALPNInfisicalPAMProxy        ALPN = "infisical-pam-proxy"
	ALPNInfisicalPAMCancellation ALPN = "infisical-pam-session-cancellation"
	ALPNInfisicalPAMCapabilities ALPN = "infisical-pam-capabilities"
)

func StartDatabaseLocalProxy(accessToken string, accessParams PAMAccessParams, projectID string, durationStr string, port int) {
	log.Info().Msgf("Starting database proxy for account: %s", accessParams.GetDisplayName())
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

	log.Info().Msgf("Database session created with ID: %s", pamResponse.SessionId)

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &DatabaseProxyServer{
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

	// For MongoDB: send a warmup connection through the gateway to trigger eager
	// topology creation (SRV resolution, TLS, SCRAM auth) and verify it works.
	// This blocks until the gateway confirms it can proxy a hello — so when the
	// user sees the connection string, mongosh will connect on the first try.
	if pamResponse.ResourceType == session.ResourceTypeMongodb {
		proxy.warmupGatewayConnection()
	}

	if port == 0 {
		fmt.Printf("Database proxy started for account %s with duration %s on port %d (auto-assigned)\n", accessParams.GetDisplayName(), duration.String(), proxy.port)
	} else {
		fmt.Printf("Database proxy started for account %s with duration %s on port %d\n", accessParams.GetDisplayName(), duration.String(), proxy.port)
	}

	username, ok := pamResponse.Metadata["username"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'username'"), "Failed to start proxy server")
		return
	}
	database, ok := pamResponse.Metadata["database"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'database'"), "Failed to start proxy server")
		return
	}

	log.Info().Msgf("Database proxy server listening on port %d", proxy.port)
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("                  Database Proxy Session Started!                  \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("Resource: %s\n", accessParams.ResourceName)
	fmt.Printf("Account:  %s\n", accessParams.AccountName)
	fmt.Printf("\n")
	fmt.Printf("You can now connect to your database using this connection string:\n")

	switch pamResponse.ResourceType {
	case session.ResourceTypePostgres:
		util.PrintfStderr("postgres://%s@localhost:%d/%s", username, proxy.port, database)
	case session.ResourceTypeMysql:
		util.PrintfStderr("mysql://%s@localhost:%d/%s", username, proxy.port, database)
	case session.ResourceTypeMssql:
		util.PrintfStderr("sqlserver://%s@localhost:%d?database=%s&encrypt=false&trustServerCertificate=true", username, proxy.port, database)
	case session.ResourceTypeMongodb:
		util.PrintfStderr("mongodb://localhost:%d/%s", proxy.port, database)
	default:
		util.PrintfStderr("localhost:%d", proxy.port)
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
			// Check if session has expired
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

			// Track active connection
			p.activeConnections.Add(1)
			go p.handleConnection(conn)
		}
	}
}

// warmupGatewayConnection sends a MongoDB hello through the full proxy chain
// (relay → gateway → MongoDB) to force topology creation and verify it works.
// When this returns, the gateway's topology is warm and the first real mongosh
// connection will succeed without the ~3-5s creation delay.
func (p *DatabaseProxyServer) warmupGatewayConnection() {
	relayConn, err := p.CreateRelayConnection()
	if err != nil {
		log.Debug().Err(err).Msg("MongoDB warmup: failed to connect to relay")
		return
	}
	defer relayConn.Close()

	gatewayConn, err := p.CreateGatewayConnection(relayConn, ALPNInfisicalPAMProxy)
	if err != nil {
		log.Debug().Err(err).Msg("MongoDB warmup: failed to connect to gateway")
		return
	}
	defer gatewayConn.Close()

	// Set a deadline — topology creation (SRV + TLS + SCRAM) can take a while,
	// but if it exceeds 15s something is wrong. Don't block the user forever.
	gatewayConn.SetDeadline(time.Now().Add(15 * time.Second))

	// Send a minimal MongoDB OP_MSG {hello: 1, $db: "admin"} through the pipe.
	// The gateway will create the topology (if needed), check out a connection,
	// forward the hello to the real server, and send the response back.
	// Reading the response confirms the full chain works.
	//
	// Wire format: header(16) + flagBits(4) + kind(1) + BSON(31) = 52 bytes
	helloMsg := []byte{
		// --- MsgHeader ---
		0x34, 0x00, 0x00, 0x00, // messageLength: 52
		0x01, 0x00, 0x00, 0x00, // requestID: 1
		0x00, 0x00, 0x00, 0x00, // responseTo: 0
		0xDD, 0x07, 0x00, 0x00, // opCode: 2013 (OP_MSG)
		// --- OP_MSG ---
		0x00, 0x00, 0x00, 0x00, // flagBits: 0
		0x00,                   // kind: 0 (body)
		// --- BSON: {hello: 1, $db: "admin"} ---
		0x1F, 0x00, 0x00, 0x00, // document length: 31
		0x10,                                           // type: int32
		0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00,             // key: "hello"
		0x01, 0x00, 0x00, 0x00,                         // value: 1
		0x02,                                           // type: string
		0x24, 0x64, 0x62, 0x00,                         // key: "$db"
		0x06, 0x00, 0x00, 0x00,                         // string length: 6 (incl. null)
		0x61, 0x64, 0x6D, 0x69, 0x6E, 0x00,             // value: "admin"
		0x00, // document terminator
	}

	if _, err := gatewayConn.Write(helloMsg); err != nil {
		log.Debug().Err(err).Msg("MongoDB warmup: failed to send hello")
		return
	}

	// Read the response header (4 bytes = message length), then the rest.
	var lengthBuf [4]byte
	if _, err := io.ReadFull(gatewayConn, lengthBuf[:]); err != nil {
		log.Debug().Err(err).Msg("MongoDB warmup: failed to read response length")
		return
	}
	respLen := int(lengthBuf[0]) | int(lengthBuf[1])<<8 | int(lengthBuf[2])<<16 | int(lengthBuf[3])<<24
	if respLen < 16 || respLen > 48*1024*1024 {
		log.Debug().Int("respLen", respLen).Msg("MongoDB warmup: invalid response length")
		return
	}
	// Drain the rest of the response (we don't need to parse it)
	if _, err := io.CopyN(io.Discard, gatewayConn, int64(respLen-4)); err != nil {
		log.Debug().Err(err).Msg("MongoDB warmup: failed to read response body")
		return
	}

	log.Debug().Msg("MongoDB warmup: topology is ready")
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

	// Gateway → Client: if this side closes first, the gateway dropped the connection
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

	// Client → Gateway: if this side closes first, the client disconnected normally
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
