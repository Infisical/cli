package pam

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type SSHProxyServer struct {
	BaseProxyServer // Embed common functionality
	server          net.Listener
	port            int
	sshProcess      *exec.Cmd
}

func StartSSHLocalProxy(accessToken string, accountID string, durationStr string) {
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

	// Verify this is an SSH resource
	if pamResponse.ResourceType != session.ResourceTypeSSH {
		util.HandleError(fmt.Errorf("account is not an SSH resource, got: %s", pamResponse.ResourceType), "Invalid resource type")
		return
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &SSHProxyServer{
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
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
		},
	}

	// Start the local TCP proxy on a random port
	err = proxy.Start(0) // 0 = random port
	if err != nil {
		util.HandleError(err, "Failed to start SSH proxy server")
		return
	}

	// Extract metadata
	username, ok := pamResponse.Metadata["username"]
	if !ok {
		util.HandleError(fmt.Errorf("PAM response metadata is missing 'username'"), "Failed to start proxy server")
		return
	}

	log.Debug().
		Str("sessionID", pamResponse.SessionId).
		Str("username", username).
		Int("port", proxy.port).
		Msg("SSH proxy ready")

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Debug().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	// Start the proxy server in a goroutine
	go proxy.Run()

	// Give the proxy a moment to start accepting connections
	time.Sleep(500 * time.Millisecond)

	// Launch SSH client connected to the local proxy (transparent to user)
	err = proxy.launchSSHClient(username)
	if err != nil {
		log.Error().Err(err).Msg("Failed to launch SSH client")
		proxy.gracefulShutdown()
		return
	}

	// Wait for SSH process to complete
	proxy.waitForSSHCompletion()

	// SSH client exited, shutdown gracefully
	proxy.gracefulShutdown()
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

func (p *SSHProxyServer) launchSSHClient(username string) error {
	// Build SSH command: ssh -p <local-port> <username>@localhost
	sshArgs := []string{
		"-p", strconv.Itoa(p.port),
		"-o", "StrictHostKeyChecking=no", // Skip host key verification (we're connecting to localhost)
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		fmt.Sprintf("%s@127.0.0.1", username),
	}

	p.sshProcess = exec.Command("ssh", sshArgs...)
	p.sshProcess.Stdin = os.Stdin
	p.sshProcess.Stdout = os.Stdout
	p.sshProcess.Stderr = os.Stderr

	log.Debug().Msgf("Executing: ssh %s", strings.Join(sshArgs, " "))

	err := p.sshProcess.Start()
	if err != nil {
		return fmt.Errorf("failed to start SSH client: %w", err)
	}

	log.Debug().Msgf("SSH client started with PID: %d", p.sshProcess.Process.Pid)
	return nil
}

func (p *SSHProxyServer) waitForSSHCompletion() {
	if p.sshProcess == nil {
		return
	}

	err := p.sshProcess.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Debug().Msgf("SSH client exited with code: %d", exitErr.ExitCode())
		} else {
			log.Error().Err(err).Msg("Error waiting for SSH client")
		}
	} else {
		log.Debug().Msg("SSH client exited successfully")
	}
}

func (p *SSHProxyServer) gracefulShutdown() {
	p.shutdownOnce.Do(func() {
		log.Debug().Msg("Starting graceful shutdown of SSH proxy...")

		// Kill SSH process if it's still running
		if p.sshProcess != nil && p.sshProcess.Process != nil {
			log.Debug().Msg("Terminating SSH client process")
			p.sshProcess.Process.Signal(syscall.SIGTERM)
		}

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

	errCh := make(chan error, 2)

	// Bidirectional data forwarding with context cancellation
	// Client (local SSH) → Gateway (SSH proxy)
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

	// Gateway (SSH proxy) → Client (local SSH)
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

	select {
	case <-errCh:
	case <-connCtx.Done():
		log.Debug().Msg("Connection cancelled by context")
	}

	log.Debug().Msgf("SSH connection closed for client: %s", clientConn.RemoteAddr().String())
}
