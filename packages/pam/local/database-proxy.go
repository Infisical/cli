package pam

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/manifoldco/promptui"
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

func askForApprovalRequestTrigger() (bool, error) {
	prompt := promptui.Prompt{
		Label:     "This action requires approval. You may create an approval request now. Continue?",
		IsConfirm: true,
	}
	result, err := prompt.Run()
	if err != nil {
		return false, err
	}
	return strings.ToLower(result) == "y", nil
}

func StartDatabaseLocalProxy(accessToken string, accountPath string, projectID string, durationStr string, port int) {
	log.Info().Msgf("Starting database proxy for account: %s", accountPath)
	log.Info().Msgf("Session duration: %s", durationStr)

	httpClient := resty.New()
	httpClient.SetAuthToken(accessToken)
	httpClient.SetHeader("User-Agent", "infisical-cli")

	pamRequest := api.PAMAccessRequest{
		Duration:    durationStr,
		AccountPath: accountPath,
		ProjectId:   projectID,
	}

	pamResponse, err := CallPAMAccessWithMFA(httpClient, pamRequest)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorMessage == "A policy is in place for this resource" {
			if v, ok := apiErr.Details.(map[string]any); ok {
				log.Info().Msgf("Account is protected by approval policy: %s", v["policyName"])

				shouldSendRequest, err := askForApprovalRequestTrigger()
				if err != nil {
					if errors.Is(err, promptui.ErrAbort) {
						log.Info().Msgf("Approval request was not created.")
					} else {
						util.HandleError(err, "Failed to send PAM account request")
					}
					return
				}

				if !shouldSendRequest {
					log.Info().Msgf("Approval request was not created.")
					return
				}

				approvalReq, err := api.CallPAMAccessApprovalRequest(httpClient, api.PAMAccessApprovalRequest{
					ProjectId: projectID,
					RequestData: api.PAMAccessApprovalRequestPayloadRequestData{
						AccountPath:    accountPath,
						AccessDuration: durationStr,
					},
				})
				if err != nil {
					util.HandleError(err, "Failed to send PAM account request")
					return
				}

				url := fmt.Sprintf("%s/organizations/%s/projects/pam/%s/approval-requests/%s", strings.TrimSuffix(config.INFISICAL_URL, "/api"), approvalReq.Request.OrgId, approvalReq.Request.ProjectId, approvalReq.Request.ID)
				if err := util.OpenBrowser(url); err != nil {
					log.Error().Msgf("Failed to do browser redirect: %v", err)
				}
				log.Info().Msgf("Approval request created.")
				log.Info().Msgf("View details at: %s", url)
				return
			}
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

	if port == 0 {
		util.PrintfStderr("Database proxy started for account %s with duration %s on port %d (auto-assigned)\n", accountPath, duration.String(), proxy.port)
	} else {
		util.PrintfStderr("Database proxy started for account %s with duration %s on port %d\n", accountPath, duration.String(), proxy.port)
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
	accountName, ok := pamResponse.Metadata["accountName"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'accountName'"), "Failed to start proxy server")
		return
	}
	accountPathMetadata, ok := pamResponse.Metadata["accountPath"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'accountPath'"), "Failed to start proxy server")
		return
	}

	log.Info().Msgf("Database proxy server listening on port %d", proxy.port)
	util.PrintfStderr("\n")
	util.PrintfStderr("**********************************************************************\n")
	util.PrintfStderr("                  Database Proxy Session Started!                  \n")
	util.PrintfStderr("----------------------------------------------------------------------\n")
	util.PrintfStderr("Accessing account %s at folder path %s\n", accountName, accountPathMetadata)
	util.PrintfStderr("\n")
	util.PrintfStderr("You can now connect to your database using this connection string:\n")

	switch pamResponse.ResourceType {
	case session.ResourceTypePostgres:
		util.PrintfStderr("postgres://%s@localhost:%d/%s", username, proxy.port, database)
	case session.ResourceTypeMysql:
		util.PrintfStderr("mysql://%s@localhost:%d/%s", username, proxy.port, database)
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
