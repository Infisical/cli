package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// SSHProxyConfig holds configuration for the SSH proxy
type SSHProxyConfig struct {
	TargetAddr        string // e.g., "target-host:22"
	AuthMethod        string
	InjectUsername    string
	InjectPassword    string
	InjectPrivateKey  string
	InjectCertificate string
	SessionID         string
	SessionLogger     session.SessionLogger
}

// SSHProxy handles proxying SSH connections with credential injection
type SSHProxy struct {
	config           SSHProxyConfig
	mutex            sync.Mutex
	sessionData      []byte                      // Store session data for logging
	inputBuffer      []byte                      // Buffer for input data to batch keystrokes
	inputChannelType session.TerminalChannelType // Channel type for buffered input
}

// channelState holds per-channel state for tracking session type
type channelState struct {
	mutex           sync.Mutex
	channelType     session.TerminalChannelType // Type of channel (terminal, exec, sftp)
	isBinarySession bool                        // True if this channel is SFTP/SCP binary protocol
	sftpParser      *SFTPParser                 // Parser for SFTP protocol to extract file operations
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
	case "certificate":
		// Parse private key
		signer, err := ssh.ParsePrivateKey([]byte(p.config.InjectPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		// Parse the certificate
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.config.InjectCertificate))
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("parsed key is not a certificate")
		}
		// Create a certificate signer
		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate signer: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(certSigner))
		log.Debug().
			Str("sessionID", p.config.SessionID).
			Msg("Using certificate authentication")
	case "password":
		authMethods = append(authMethods, ssh.Password(p.config.InjectPassword))
		log.Debug().
			Str("sessionID", p.config.SessionID).
			Msg("Using password authentication")
	default:
		return nil, fmt.Errorf("invalid or unspecified auth method: %s (must be 'public-key', 'certificate', or 'password')", p.config.AuthMethod)
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
	// Accept the channel from client
	clientChannel, clientRequests, err := newChannel.Accept()
	if err != nil {
		log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to accept client channel")
		serverChannel.Close()
		return
	}

	log.Info().
		Str("sessionID", sessionID).
		Str("channelType", channelType).
		Msg("SSH channel established")

	// Create per-channel state for tracking binary sessions (SFTP/SCP)
	chState := &channelState{}

	// Separate done channels to ensure exit-status is forwarded before channel teardown.
	serverReqDone := make(chan struct{})
	clientReqDone := make(chan struct{})
	go func() {
		defer close(clientReqDone)
		p.handleChannelRequests(clientRequests, serverChannel, sessionID, channelType, chState)
	}()
	go func() {
		defer close(serverReqDone)
		p.handleChannelRequests(serverRequests, clientChannel, sessionID, channelType, chState)
	}()

	// Proxy data bidirectionally with logging
	errChan := make(chan error, 2)

	// Client to Server
	go func() {
		err := p.proxyData(clientChannel, serverChannel, "client→server", sessionID, true, chState)
		// Signal the server that the client is done writing so the remote process
		// receives EOF and can exit, which triggers exit-status delivery.
		serverChannel.CloseWrite()
		errChan <- err
	}()

	// Server to Client
	go func() {
		err := p.proxyData(serverChannel, clientChannel, "server→client", sessionID, false, chState)
		errChan <- err
	}()

	// Wait for BOTH directions to finish (or context cancellation).
	// Previously only one direction was awaited, which caused premature teardown
	// for SCP: the client→server copy would finish first (file data sent), but the
	// server had not yet delivered exit-status. Waiting for both directions ensures
	// the server's data EOF (which follows exit-status) is observed before teardown.
	for i := 0; i < 2; i++ {
		select {
		case err := <-errChan:
			if err != nil && err != io.EOF {
				log.Debug().Err(err).Str("sessionID", sessionID).Msg("Channel proxy error")
			}
		case <-ctx.Done():
			log.Info().Str("sessionID", sessionID).Msg("Channel cancelled by context")
		}
	}

	// Wait for the server-side channel requests handler to finish so that any
	// remaining requests (exit-status, exit-signal) are forwarded to the client
	// before we tear down the channels.
	select {
	case <-serverReqDone:
	case <-time.After(3 * time.Second):
		log.Debug().Str("sessionID", sessionID).Msg("Timed out waiting for server requests to complete")
	}
	clientChannel.Close()
	serverChannel.Close()
	<-clientReqDone

	log.Debug().
		Str("sessionID", sessionID).
		Str("channelType", channelType).
		Msg("SSH channel closed")
}

// handleChannelRequests handles channel-specific requests (pty, shell, exec, etc.)
func (p *SSHProxy) handleChannelRequests(requests <-chan *ssh.Request, targetChannel ssh.Channel, sessionID string, channelType string, chState *channelState) {
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
			// SSH exec payload format: uint32 length (big-endian) + command string
			if len(req.Payload) >= 4 {
				cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
				if len(req.Payload) >= 4+cmdLen {
					command := string(req.Payload[4 : 4+cmdLen])

					// Determine the type of operation
					isSCP := strings.HasPrefix(command, "scp ")
					chState.mutex.Lock()
					if isSCP {
						// Mark this channel as binary so we don't log the raw file data
						chState.isBinarySession = true
						chState.channelType = session.TerminalChannelSFTP // SCP is file transfer
					} else {
						chState.channelType = session.TerminalChannelExec
					}
					chState.mutex.Unlock()

					log.Info().
						Str("sessionID", sessionID).
						Str("command", command).
						Msg("SSH exec command")

					// Log the exec command to the session recording
					var logMessage string
					var channelType session.TerminalChannelType
					if isSCP {
						channelType = session.TerminalChannelSFTP
						// Parse SCP command for more readable logging
						// scp -t /path = receiving file TO server
						// scp -f /path = sending file FROM server
						if strings.Contains(command, " -t ") {
							path := extractSCPPath(command)
							logMessage = fmt.Sprintf("Uploaded file: %s\n", path)
						} else if strings.Contains(command, " -f ") {
							path := extractSCPPath(command)
							logMessage = fmt.Sprintf("Downloaded file: %s\n", path)
						} else {
							logMessage = fmt.Sprintf("$ %s\n", command)
						}
					} else {
						channelType = session.TerminalChannelExec
						logMessage = fmt.Sprintf("$ %s\n", command)
					}

					event := session.TerminalEvent{
						Timestamp:   time.Now(),
						EventType:   session.TerminalEventInput,
						ChannelType: channelType,
						Data:        []byte(logMessage),
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
			chState.mutex.Lock()
			chState.channelType = session.TerminalChannelShell
			chState.mutex.Unlock()
			log.Info().
				Str("sessionID", sessionID).
				Msg("SSH interactive shell requested")
		case "subsystem":
			// Subsystem requests are used by SFTP (and potentially other subsystems)
			// Payload format: uint32 length (big-endian) + subsystem name
			if len(req.Payload) >= 4 {
				subsysLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
				if len(req.Payload) >= 4+subsysLen {
					subsystem := string(req.Payload[4 : 4+subsysLen])
					log.Info().
						Str("sessionID", sessionID).
						Str("subsystem", subsystem).
						Msg("SSH subsystem requested")

					// Log SFTP sessions and set up SFTP parser for file operation logging
					if subsystem == "sftp" {
						chState.mutex.Lock()
						chState.channelType = session.TerminalChannelSFTP
						chState.isBinarySession = true
						chState.sftpParser = NewSFTPParser()
						chState.mutex.Unlock()

						event := session.TerminalEvent{
							Timestamp:   time.Now(),
							EventType:   session.TerminalEventInput,
							ChannelType: session.TerminalChannelSFTP,
							Data:        []byte("File transfer session started\n"),
						}
						if err := p.config.SessionLogger.LogTerminalEvent(event); err != nil {
							log.Error().Err(err).
								Str("sessionID", sessionID).
								Msg("Failed to log SFTP session start")
						} else {
							log.Info().
								Str("sessionID", sessionID).
								Msg("Successfully logged SFTP session start event")
						}
					}
				}
			}
		case "pty-req":
			log.Debug().
				Str("sessionID", sessionID).
				Msg("PTY requested")
		}

		// Forward request to target channel
		ok, err := targetChannel.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			// EOF errors on exit-status/exit-signal are expected when channel closes
			// before the status can be forwarded - this is normal, not an error
			if err == io.EOF && (req.Type == "exit-status" || req.Type == "exit-signal") {
				log.Debug().
					Str("sessionID", sessionID).
					Str("requestType", req.Type).
					Msg("Channel closed before forwarding exit status (normal)")
			} else {
				log.Error().Err(err).
					Str("sessionID", sessionID).
					Str("requestType", req.Type).
					Msg("Failed to forward channel request")
			}
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
func (p *SSHProxy) proxyData(src io.Reader, dst io.Writer, direction string, sessionID string, logInput bool, chState *channelState) error {
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
			// Check if this channel is a binary session (SFTP/SCP)
			chState.mutex.Lock()
			isBinary := chState.isBinarySession
			sftpParser := chState.sftpParser
			channelType := chState.channelType
			chState.mutex.Unlock()

			if isBinary && sftpParser != nil && logInput {
				// Parse SFTP packets from client->server direction to extract file operations
				operations := sftpParser.Parse(buf[:n])
				for _, op := range operations {
					// Log each SFTP operation
					logMsg := FormatOperation(op) + "\n"
					event := session.TerminalEvent{
						Timestamp:   time.Now(),
						EventType:   session.TerminalEventInput,
						ChannelType: session.TerminalChannelSFTP,
						Data:        []byte(logMsg),
					}
					if err := p.config.SessionLogger.LogTerminalEvent(event); err != nil {
						log.Error().Err(err).
							Str("sessionID", sessionID).
							Str("operation", op.Type).
							Str("path", op.Path).
							Msg("Failed to log SFTP operation")
					} else {
						log.Debug().
							Str("sessionID", sessionID).
							Str("operation", op.Type).
							Str("path", op.Path).
							Msg("Logged SFTP operation")
					}
				}
			} else if !isBinary {
				// Regular terminal session logging
				if logInput {
					p.bufferInput(buf[:n], sessionID, channelType)
				} else {
					// For output, log immediately as before
					event := session.TerminalEvent{
						Timestamp:   time.Now(),
						EventType:   session.TerminalEventOutput,
						ChannelType: channelType,
						Data:        make([]byte, n),
					}
					copy(event.Data, buf[:n])

					if err := p.config.SessionLogger.LogTerminalEvent(event); err != nil {
						log.Error().Err(err).
							Str("sessionID", sessionID).
							Str("eventType", string(session.TerminalEventOutput)).
							Msg("Failed to log terminal event")
					}
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

// bufferInput accumulates input data and logs the effective command after processing edits.
// It interprets control characters (backspace, Ctrl+C/U/W) so that the logged command
// reflects what the user actually sent, not the raw keystrokes.
func (p *SSHProxy) bufferInput(data []byte, sessionID string, channelType session.TerminalChannelType) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.inputChannelType = channelType

	for _, b := range data {
		switch b {
		case 0x7F, 0x08: // DEL (backspace on most terminals) or BS
			if len(p.inputBuffer) > 0 {
				p.inputBuffer = p.inputBuffer[:len(p.inputBuffer)-1]
			}
		case 0x03: // Ctrl+C - cancel current input
			p.inputBuffer = p.inputBuffer[:0]
		case 0x15: // Ctrl+U - clear line
			p.inputBuffer = p.inputBuffer[:0]
		case 0x17: // Ctrl+W - delete previous word
			// Skip trailing spaces
			for len(p.inputBuffer) > 0 && p.inputBuffer[len(p.inputBuffer)-1] == ' ' {
				p.inputBuffer = p.inputBuffer[:len(p.inputBuffer)-1]
			}
			// Delete until next space or start
			for len(p.inputBuffer) > 0 && p.inputBuffer[len(p.inputBuffer)-1] != ' ' {
				p.inputBuffer = p.inputBuffer[:len(p.inputBuffer)-1]
			}
		case 0x0D, 0x0A: // CR or LF - flush the buffer
			p.inputBuffer = append(p.inputBuffer, b)
			p.flushInputBufferUnsafe(sessionID)
		default:
			// Only buffer printable characters and tab
			if b >= 0x20 || b == 0x09 {
				p.inputBuffer = append(p.inputBuffer, b)
			}
			// Safety: flush if buffer gets too large
			if len(p.inputBuffer) >= 1024 {
				p.flushInputBufferUnsafe(sessionID)
			}
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
		Timestamp:   time.Now(),
		EventType:   session.TerminalEventInput,
		ChannelType: p.inputChannelType,
		Data:        make([]byte, len(p.inputBuffer)),
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

// extractSCPPath extracts the file path from an SCP command
// SCP commands look like: scp -t /path/to/file or scp -f /path/to/file
func extractSCPPath(command string) string {
	parts := strings.Fields(command)
	if len(parts) >= 3 {
		// The path is typically the last argument
		return parts[len(parts)-1]
	}
	return "<unknown path>"
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
