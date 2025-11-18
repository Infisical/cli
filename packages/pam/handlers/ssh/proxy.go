package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// SSHProxyConfig holds configuration for the SSH proxy
type SSHProxyConfig struct {
	TargetAddr       string // e.g., "target-host:22"
	AuthMethod       string
	InjectUsername   string
	InjectPassword   string
	InjectPrivateKey string
	SessionID        string
	SessionLogger    session.SessionLogger
}

// SSHProxy handles proxying SSH connections with credential injection
type SSHProxy struct {
	config      SSHProxyConfig
	mutex       sync.Mutex
	sessionData []byte // Store session data for logging
	inputBuffer []byte // Buffer for input data to batch keystrokes
}

// NewSSHProxy creates a new SSH proxy instance
func NewSSHProxy(config SSHProxyConfig) *SSHProxy {
	return &SSHProxy{
		config: config,
	}
}

// HandleConnection handles a single SSH client connection
func (p *SSHProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	sessionID := p.config.SessionID

	// Ensure session logger cleanup
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().
		Str("sessionID", sessionID).
		Str("targetAddr", p.config.TargetAddr).
		Msg("New SSH connection for PAM session")

	// Configure SSH server (proxy acts as SSH server to the client)
	serverConfig := &ssh.ServerConfig{
		// Accept any credentials from client - we'll inject our own to the target
		NoClientAuth: true,
		// Alternative: accept any password
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}

	// Generate a temporary host key for the proxy
	hostKey, err := p.generateHostKey()
	if err != nil {
		log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to generate host key")
		return fmt.Errorf("failed to generate host key: %w", err)
	}

	serverConfig.AddHostKey(hostKey)

	// Perform SSH handshake with client
	clientSSHConn, clientChannels, clientRequests, err := ssh.NewServerConn(clientConn, serverConfig)
	if err != nil {
		log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to establish SSH server connection with client")
		return fmt.Errorf("failed to establish SSH connection with client: %w", err)
	}
	defer clientSSHConn.Close()

	log.Info().
		Str("sessionID", sessionID).
		Str("clientUser", clientSSHConn.User()).
		Str("clientVersion", string(clientSSHConn.ClientVersion())).
		Msg("SSH client connected")

	// Connect to target SSH server with injected credentials
	serverSSHConn, err := p.connectToTargetServer()
	if err != nil {
		log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to connect to target SSH server")
		return fmt.Errorf("failed to connect to target SSH server: %w", err)
	}
	defer serverSSHConn.Close()

	log.Info().
		Str("sessionID", sessionID).
		Str("serverVersion", string(serverSSHConn.ServerVersion())).
		Msg("Connected to target SSH server with injected credentials")

	// Discard global requests (not needed for basic remote access)
	go ssh.DiscardRequests(clientRequests)

	// Handle channels from client (this is where actual SSH sessions happen)
	for newChannel := range clientChannels {
		go p.handleChannel(ctx, newChannel, serverSSHConn, sessionID)
	}

	log.Info().
		Str("sessionID", sessionID).
		Msg("SSH connection closed")

	return nil
}

// connectToTargetServer establishes connection to the actual SSH server with injected credentials
func (p *SSHProxy) connectToTargetServer() (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	switch p.config.AuthMethod {
	case "public-key":
		// Parse private key (convert PEM string to bytes)
		signer, err := ssh.ParsePrivateKey([]byte(p.config.InjectPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
		log.Debug().
			Str("sessionID", p.config.SessionID).
			Msg("Using public key authentication")
	case "password":
		authMethods = append(authMethods, ssh.Password(p.config.InjectPassword))
		log.Debug().
			Str("sessionID", p.config.SessionID).
			Msg("Using password authentication")
	default:
		return nil, fmt.Errorf("invalid or unspecified auth method: %s (must be 'public-key' or 'password')", p.config.AuthMethod)
	}

	// Configure SSH client (proxy acts as client to the target server)
	clientConfig := &ssh.ClientConfig{
		User:            p.config.InjectUsername,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: add support for passing in host key
		Timeout:         10 * time.Second,
	}

	// Connect to target server
	client, err := ssh.Dial("tcp", p.config.TargetAddr, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial target SSH server: %w", err)
	}

	return client, nil
}

// handleChannel handles a single SSH channel (session, direct-tcpip, etc.)
func (p *SSHProxy) handleChannel(ctx context.Context, newChannel ssh.NewChannel, serverConn *ssh.Client, sessionID string) {
	channelType := newChannel.ChannelType()

	log.Debug().
		Str("sessionID", sessionID).
		Str("channelType", channelType).
		Msg("← CLIENT new channel request")

	// Open corresponding channel on server
	serverChannel, serverRequests, err := serverConn.OpenChannel(channelType, newChannel.ExtraData())
	if err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Str("channelType", channelType).
			Msg("Failed to open channel on server")
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to open channel: %v", err))
		return
	}
	defer serverChannel.Close()

	// Accept the channel from client
	clientChannel, clientRequests, err := newChannel.Accept()
	if err != nil {
		log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to accept client channel")
		serverChannel.Close()
		return
	}
	defer clientChannel.Close()

	log.Info().
		Str("sessionID", sessionID).
		Str("channelType", channelType).
		Msg("SSH channel established")

	// Handle requests for this channel (pty-req, shell, exec, etc.)
	go p.handleChannelRequests(clientRequests, serverChannel, sessionID, channelType)
	go p.handleChannelRequests(serverRequests, clientChannel, sessionID, channelType)

	// Proxy data bidirectionally with logging
	errChan := make(chan error, 2)

	// Client to Server
	go func() {
		err := p.proxyData(clientChannel, serverChannel, "client→server", sessionID, true)
		errChan <- err
	}()

	// Server to Client
	go func() {
		err := p.proxyData(serverChannel, clientChannel, "server→client", sessionID, false)
		errChan <- err
	}()

	// Wait for either direction to finish or context cancellation
	select {
	case err := <-errChan:
		if err != nil && err != io.EOF {
			log.Debug().Err(err).Str("sessionID", sessionID).Msg("Channel proxy error")
		}
	case <-ctx.Done():
		log.Info().Str("sessionID", sessionID).Msg("Channel cancelled by context")
	}

	log.Debug().
		Str("sessionID", sessionID).
		Str("channelType", channelType).
		Msg("SSH channel closed")
}

// handleChannelRequests handles channel-specific requests (pty, shell, exec, etc.)
func (p *SSHProxy) handleChannelRequests(requests <-chan *ssh.Request, targetChannel ssh.Channel, sessionID string, channelType string) {
	for req := range requests {
		log.Debug().
			Str("sessionID", sessionID).
			Str("channelType", channelType).
			Str("requestType", req.Type).
			Bool("wantReply", req.WantReply).
			Msg("Channel request")

		// Log exec and shell requests for audit
		switch req.Type {
		case "exec":
			if len(req.Payload) > 4 {
				cmdLen := int(req.Payload[3])
				if len(req.Payload) >= 4+cmdLen {
					command := string(req.Payload[4 : 4+cmdLen])
					log.Info().
						Str("sessionID", sessionID).
						Str("command", command).
						Msg("SSH exec command")

					// Log the exec command to the session recording
					// Format it similar to how it would appear in a shell
					commandWithPrompt := fmt.Sprintf("$ %s\n", command)
					event := session.TerminalEvent{
						Timestamp: time.Now(),
						EventType: session.TerminalEventInput,
						Data:      []byte(commandWithPrompt),
					}
					if err := p.config.SessionLogger.LogTerminalEvent(event); err != nil {
						log.Error().Err(err).
							Str("sessionID", sessionID).
							Str("command", command).
							Msg("Failed to log exec command to session recording")
					}
				}
			}
		case "shell":
			log.Info().
				Str("sessionID", sessionID).
				Msg("SSH interactive shell requested")
		case "pty-req":
			log.Debug().
				Str("sessionID", sessionID).
				Msg("PTY requested")
		}

		// Forward request to target channel
		ok, err := targetChannel.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			log.Error().Err(err).
				Str("sessionID", sessionID).
				Str("requestType", req.Type).
				Msg("Failed to forward channel request")
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}

		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

// proxyData proxies data between channels with optional logging
func (p *SSHProxy) proxyData(src io.Reader, dst io.Writer, direction string, sessionID string, logInput bool) error {
	buf := make([]byte, 32*1024) // 32KB buffer

	// Flush any remaining input buffer on exit
	defer func() {
		if logInput && len(p.inputBuffer) > 0 {
			p.flushInputBuffer(sessionID)
		}
	}()

	for {
		n, err := src.Read(buf)
		if n > 0 {
			// For input, buffer until we see newline or control chars
			if logInput {
				p.bufferInput(buf[:n], sessionID)
			} else {
				// For output, log immediately as before
				event := session.TerminalEvent{
					Timestamp: time.Now(),
					EventType: session.TerminalEventOutput,
					Data:      make([]byte, n),
				}
				copy(event.Data, buf[:n])

				if err := p.config.SessionLogger.LogTerminalEvent(event); err != nil {
					log.Error().Err(err).
						Str("sessionID", sessionID).
						Str("eventType", string(session.TerminalEventOutput)).
						Msg("Failed to log terminal event")
				}
			}

			// Write to destination
			written, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// bufferInput accumulates input data and logs only when newline or control chars are encountered
func (p *SSHProxy) bufferInput(data []byte, sessionID string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, b := range data {
		p.inputBuffer = append(p.inputBuffer, b)

		// Check if we should flush the buffer
		// CR (0x0D), LF (0x0A), or if buffer gets too large
		if b == 0x0D || b == 0x0A || len(p.inputBuffer) >= 1024 {
			p.flushInputBufferUnsafe(sessionID)
		}
	}
}

// flushInputBuffer flushes the input buffer with locking
func (p *SSHProxy) flushInputBuffer(sessionID string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.flushInputBufferUnsafe(sessionID)
}

// flushInputBufferUnsafe flushes the input buffer without locking (caller must hold lock)
func (p *SSHProxy) flushInputBufferUnsafe(sessionID string) {
	if len(p.inputBuffer) == 0 {
		return
	}

	event := session.TerminalEvent{
		Timestamp: time.Now(),
		EventType: session.TerminalEventInput,
		Data:      make([]byte, len(p.inputBuffer)),
	}
	copy(event.Data, p.inputBuffer)

	if err := p.config.SessionLogger.LogTerminalEvent(event); err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Str("eventType", string(session.TerminalEventInput)).
			Msg("Failed to log terminal event")
	}

	// Clear the buffer
	p.inputBuffer = p.inputBuffer[:0]
}

// generateHostKey generates a temporary RSA key for the SSH server
func (p *SSHProxy) generateHostKey() (ssh.Signer, error) {
	rsaKey, err := generateRSAKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privateKey, err := ssh.NewSignerFromSigner(rsaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}
	return privateKey, nil
}
