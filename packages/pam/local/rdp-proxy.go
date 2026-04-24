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

	"github.com/Infisical/infisical-merge/packages/pam/handlers/rdp"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// RDPProxyServer exposes a local loopback TCP listener that tunnels bytes
// to the gateway's RDP MITM bridge via the existing mTLS + SSH relay. The
// user's RDP client connects to the loopback port; the gateway takes care
// of credential injection and forwarding to the Windows target.
type RDPProxyServer struct {
	BaseProxyServer
	server      net.Listener
	port        int
	rdpFilePath string // path to the generated .rdp file, if any
}

// StartRDPLocalProxy is the CLI entry point for `infisical pam rdp access`.
// It creates a PAM session with the backend, binds a loopback listener,
// writes a .rdp file pointing at that loopback, optionally launches the
// user's default RDP client, and forwards accepted connections to the
// gateway.
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

	rdpFilePath, err := writeRDPFile(proxy.port, pamResponse.SessionId)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to write .rdp file; proxy still running")
	} else {
		proxy.rdpFilePath = rdpFilePath
	}

	log.Info().Msgf("RDP proxy server listening on port %d", proxy.port)
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("                      RDP Proxy Session Started!                      \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("Resource: %s\n", accessParams.ResourceName)
	fmt.Printf("Account:  %s\n", accessParams.AccountName)
	fmt.Printf("\n")
	fmt.Printf("Connect your RDP client to:\n")
	util.PrintfStderr("  127.0.0.1:%d\n", proxy.port)
	fmt.Printf("With credentials:\n")
	util.PrintfStderr("  username: %s\n", rdp.AcceptorUsername)
	util.PrintfStderr("  password: %s\n", rdp.AcceptorPassword)
	if proxy.rdpFilePath != "" {
		fmt.Printf("\n")
		fmt.Printf("Generated .rdp file:\n")
		util.PrintfStderr("  %s\n", proxy.rdpFilePath)
	}
	util.PrintfStderr("\n")
	util.PrintfStderr("Press Ctrl+C to terminate the session.\n")
	util.PrintfStderr("**********************************************************************\n")
	util.PrintfStderr("\n")

	// The .rdp file format has no portable way to embed a plaintext password
	// (mstsc's `password 51:b:` is Windows-DPAPI-encrypted; Mac / freerdp
	// clients ignore any password field). Put the fixed acceptor password
	// on the clipboard so the user just pastes it when the client prompts.
	if err := copyToClipboard(rdp.AcceptorPassword); err != nil {
		log.Debug().Err(err).Msg("Could not copy password to clipboard; type it manually")
	} else {
		util.PrintfStderr("(Password copied to clipboard.)\n\n")
	}

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

		// Remove the .rdp file first: p.cancel() below unblocks Run(),
		// which returns to main, which may exit before the rest of this
		// goroutine completes. Do the cleanup that has to happen before
		// anything that could let main race ahead.
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

	log.Info().Msgf("RDP connection closed for client: %s", clientConn.RemoteAddr().String())
}

// writeRDPFile creates a .rdp file pointing at the local loopback
// listener. Files live under `~/.infisical/rdp/` to match the CLI's
// existing convention for per-user state (alongside the login config
// and update-check cache). Filename includes the session ID so
// concurrent sessions don't collide. The file is removed on graceful
// shutdown (see gracefulShutdown) since the embedded loopback port
// becomes invalid as soon as the CLI exits; reopening the file later
// would just dial a dead port.
// Falls back to the OS temp dir if the home directory can't be resolved.
func writeRDPFile(listenPort int, sessionID string) (string, error) {
	filename := fmt.Sprintf("infisical-rdp-%s.rdp", sessionID)

	dir, err := rdpFileDir()
	if err != nil {
		log.Debug().Err(err).Msg("Falling back to OS temp dir for .rdp file")
		dir = os.TempDir()
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create rdp dir %q: %w", dir, err)
	}
	path := filepath.Join(dir, filename)

	content := fmt.Sprintf(
		"full address:s:127.0.0.1:%d\r\n"+
			"username:s:%s\r\n",
		listenPort,
		rdp.AcceptorUsername,
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

// copyToClipboard pipes `text` into the OS clipboard via the platform's
// standard CLI helper. Failure is non-fatal; the caller logs and moves on.
func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "windows":
		cmd = exec.Command("clip")
	default:
		// Try xclip first, then xsel. Neither is guaranteed to exist on
		// headless servers, which is fine: we just return the error and
		// the caller logs at debug level.
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return fmt.Errorf("no clipboard tool found (install xclip or xsel)")
		}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte(text)); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	return cmd.Wait()
}
