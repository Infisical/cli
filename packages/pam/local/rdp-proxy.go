package pam

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// Loopback listener that tunnels RDP client traffic to the gateway's MITM bridge.
type RDPProxyServer struct {
	BaseProxyServer
	server      net.Listener
	port        int
	rdpFilePath string
}

// CLI entry point for `infisical pam rdp access`.
func StartRDPLocalProxy(accessToken string, accessParams PAMAccessParams, projectID string, durationStr string, port int, noLaunch bool) {
	log.Info().Msgf("Starting RDP proxy for account: %s", accessParams.GetDisplayName())
	log.Info().Msgf("Session duration: %s", durationStr)

	httpClient := resty.New()
	httpClient.SetAuthToken(accessToken)
	httpClient.SetHeader("User-Agent", "infisical-cli")

	pamRequest := accessParams.ToAPIRequest(projectID, durationStr)

	pamResponse, err := CallPAMAccessWithMFA(httpClient, pamRequest, true)
	if err != nil {
		if HandleApprovalWorkflow(httpClient, err, projectID, accessParams, durationStr) {
			return
		}
		util.HandleError(err, "Failed to access PAM account")
		return
	}

	log.Info().Msgf("RDP session created with ID: %s", pamResponse.SessionId)

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &RDPProxyServer{
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

	if err := proxy.Start(port); err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	username, ok := pamResponse.Metadata["username"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'username'"), "Failed to start proxy server")
		return
	}

	rdpFilePath, err := writeRDPFile(proxy.port, pamResponse.SessionId, username)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to write .rdp file; proxy still running")
	} else {
		proxy.rdpFilePath = rdpFilePath
	}

	log.Info().Msgf("RDP proxy server listening on port %d", proxy.port)
	util.PrintfStderr("\n")
	util.PrintfStderr("**********************************************************************\n")
	util.PrintfStderr("                      RDP Proxy Session Started!                      \n")
	util.PrintfStderr("----------------------------------------------------------------------\n")
	util.PrintfStderr("Resource: %s\n", accessParams.ResourceName)
	util.PrintfStderr("Account:  %s\n", accessParams.AccountName)
	util.PrintfStderr("\n")
	util.PrintfStderr("Connect your RDP client to:\n")
	util.PrintfStderr("  127.0.0.1:%d\n", proxy.port)
	util.PrintfStderr("With credentials:\n")
	util.PrintfStderr("  username: %s\n", username)
	util.PrintfStderr("  password: (leave blank)\n")
	if proxy.rdpFilePath != "" {
		util.PrintfStderr("\n")
		util.PrintfStderr("Generated .rdp file:\n")
		util.PrintfStderr("  %s\n", proxy.rdpFilePath)
	}
	util.PrintfStderr("\n")
	util.PrintfStderr("Press Ctrl+C to terminate the session.\n")
	util.PrintfStderr("**********************************************************************\n")
	util.PrintfStderr("\n")

	if !noLaunch && proxy.rdpFilePath != "" {
		if err := launchRDPClient(proxy.rdpFilePath); err != nil {
			log.Warn().Err(err).Msg("Failed to auto-launch RDP client; connect manually using the details above")
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

// Start binds the loopback listener. Port 0 picks a random free port.
func (p *RDPProxyServer) Start(port int) error {
	var err error
	if port == 0 {
		p.server, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		p.server, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	}
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	p.port = p.server.Addr().(*net.TCPAddr).Port
	return nil
}

func (p *RDPProxyServer) gracefulShutdown() {
	p.shutdownOnce.Do(func() {
		log.Info().Msg("Starting graceful shutdown of RDP proxy...")

		// p.cancel() below can return main before this goroutine finishes;
		// remove the .rdp file before risking that race.
		if p.rdpFilePath != "" {
			if err := os.Remove(p.rdpFilePath); err != nil && !os.IsNotExist(err) {
				log.Debug().Err(err).Str("path", p.rdpFilePath).Msg("Failed to remove .rdp file on exit")
			}
		}

		p.NotifySessionTermination()

		close(p.shutdownCh)

		if p.server != nil {
			p.server.Close()
		}

		p.cancel()

		p.WaitForConnectionsWithTimeout(10 * time.Second)

		log.Info().Msg("RDP proxy shutdown complete")
		os.Exit(0)
	})
}

func (p *RDPProxyServer) Run() {
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
				log.Warn().Msg("RDP session expired, shutting down proxy")
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

// handleConnection forwards bytes between the RDP client and the gateway
// tunnel. Identical shape to the database proxy; the gateway's RDP
// handler takes over on the other side.
func (p *RDPProxyServer) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.activeConnections.Done()
	}()

	log.Info().Msgf("New RDP connection from %s", clientConn.RemoteAddr())

	select {
	case <-p.ctx.Done():
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

	log.Info().Msg("Established connection to RDP resource")

	connCtx, connCancel := context.WithCancel(p.ctx)
	defer connCancel()

	done := make(chan struct{}, 2)

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
		done <- struct{}{}
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
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-connCtx.Done():
		log.Info().Msg("Connection cancelled by context")
	}

	log.Info().Msgf("RDP connection closed for client: %s", clientConn.RemoteAddr().String())
}

// Generates a per-session .rdp file under ~/.infisical/rdp/ pointing at
// the loopback listener. Removed on graceful shutdown.
func writeRDPFile(listenPort int, sessionID, username string) (string, error) {
	filename := fmt.Sprintf("infisical-rdp-%s.rdp", sessionID)

	dir, err := rdpFileDir()
	if err != nil {
		log.Debug().Err(err).Msg("Falling back to OS temp dir for .rdp file")
		dir = os.TempDir()
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create rdp dir %q: %w", dir, err)
	}
	path := filepath.Join(dir, filename)

	// authentication level:i:0 -> mstsc connects even if it can't verify the
	// server's TLS cert. The bridge presents a self-signed cert, so without
	// this mstsc terminates with "unexpected server authentication certificate".
	// FreeRDP/Windows App ignore the cert by default; mstsc is the strict one.
	content := fmt.Sprintf(
		"full address:s:127.0.0.1:%d\r\n"+
			"username:s:%s\r\n"+
			"authentication level:i:0\r\n",
		listenPort,
		username,
	)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write rdp file: %w", err)
	}
	return path, nil
}

// rdpFileDir returns ~/.infisical/rdp (the conventional per-user state
// location for CLI data; see util.CONFIG_FOLDER_NAME).
func rdpFileDir() (string, error) {
	home, err := util.GetHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, util.CONFIG_FOLDER_NAME, "rdp"), nil
}

// launchRDPClient opens the given .rdp file with the user's default RDP
// client. Failure is non-fatal; the caller can still manually connect
// using the printed connection details.
func launchRDPClient(rdpFilePath string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rdpFilePath)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", rdpFilePath)
	default:
		cmd = exec.Command("xdg-open", rdpFilePath)
	}
	return cmd.Start()
}
