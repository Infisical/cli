package pam

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

// Loopback listener that tunnels RDP client traffic to the gateway's MITM bridge.
type RDPProxyServer struct {
	BaseProxyServer
	server      net.Listener
	port        int
	rdpFilePath string
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

		// Remove before cancel() can return main
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

// handleConnection forwards bytes between the RDP client and the gateway tunnel.
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

// Generates a per-session .rdp file; removed on graceful shutdown.
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

	// auth level 0: bridge presents self-signed cert, mstsc rejects without this
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

// rdpFileDir returns ~/.infisical/rdp.
func rdpFileDir() (string, error) {
	home, err := util.GetHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, util.CONFIG_FOLDER_NAME, "rdp"), nil
}

// launchRDPClient opens the .rdp file with the default client. Non-fatal on failure.
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
