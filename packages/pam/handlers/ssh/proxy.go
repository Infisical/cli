package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// SSHProxyConfig holds configuration for the SSH proxy
type SSHProxyConfig struct {
	TargetAddr             string // e.g., "target-host:22"
	AuthMethod             string
	InjectUsername         string
	InjectPassword         string
	InjectPrivateKey       string
	InjectCertificate      string
	SessionID              string
	SessionLogger          session.SessionLogger
	BlockedCommandPatterns []*regexp.Regexp // Regex patterns for command blocking (nil = no blocking)
	OnActivity             func()           // Called when channel data flows
}

// SSHProxy handles proxying SSH connections with credential injection
type SSHProxy struct {
	config SSHProxyConfig
}

// channelState holds per-channel state. A client can open channels concurrently, so
// sharing recording state would interleave two channels into one transcript.
type channelState struct {
	mutex           sync.Mutex
	channelType     session.SessionChannelType // Type of channel (terminal, exec, sftp)
	isBinarySession bool                       // True if this channel is SFTP/SCP binary protocol
	sftpParser      *SFTPParser                // Parser for SFTP protocol to extract file operations

	inputMutex       sync.Mutex
	inputBuffer      []byte                     // Buffer for input data to batch keystrokes
	inputChannelType session.SessionChannelType // Channel type for buffered input
	inputScanner     *inputSequenceFilter       // Drops escape sequences from the input stream
	pendingEcho      echoedCommand              // Command awaiting confirmation that the shell echoed it
	echoBaseline     int                        // Length of the line on screen when the command started

	outputMutex       sync.Mutex
	outputParser      *terminalTranscript        // Renders the output stream into displayed lines
	outputChannelType session.SessionChannelType // Channel type for buffered output
	outputPending     atomic.Int64               // Rendered length of the line still on screen
}

func newChannelState() *channelState {
	return &channelState{
		inputScanner: newInputSequenceFilter(),
		outputParser: newTerminalTranscript(),
	}
}

func (c *channelState) textEvent(eventType session.SessionEventType, channelType session.SessionChannelType, text string) session.SessionEvent {
	return session.SessionEvent{
		Timestamp:   time.Now(),
		EventType:   eventType,
		ChannelType: channelType,
		Data:        []byte(text),
		Rendered:    true,
	}
}

// NewSSHProxy creates a new SSH proxy instance
func NewSSHProxy(config SSHProxyConfig) *SSHProxy {
	return &SSHProxy{config: config}
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

	// SSH keepalive: detect dead connections where TCP goes silent. Probes both sides every 30s
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := util.SSHKeepalive(clientSSHConn, 15*time.Second); err != nil {
					log.Info().Err(err).Str("sessionID", sessionID).Msg("SSH keepalive to client failed, tearing down connection")
					clientConn.Close()
					return
				}
				if err := util.SSHKeepalive(serverSSHConn, 15*time.Second); err != nil {
					log.Info().Err(err).Str("sessionID", sessionID).Msg("SSH keepalive to target failed, tearing down connection")
					clientConn.Close()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

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
	chState := newChannelState()

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

	clientToServerDone := make(chan error, 1)
	serverToClientDone := make(chan error, 1)

	// Client to Server
	go func() {
		var err error
		if len(p.config.BlockedCommandPatterns) > 0 {
			err = p.proxyClientToServerWithBlocking(clientChannel, serverChannel, clientChannel, sessionID, chState)
		} else {
			err = p.proxyData(clientChannel, serverChannel, "client→server", sessionID, true, chState)
		}
		// Send EOF so the remote process exits and delivers exit-status.
		serverChannel.CloseWrite() //nolint:errcheck
		clientToServerDone <- err
	}()

	// Server to Client
	go func() {
		err := p.proxyData(serverChannel, clientChannel, "server→client", sessionID, false, chState)
		serverToClientDone <- err
	}()

	// When client→server finishes first (SCP), wait for server→client to deliver
	// the response. When server→client finishes first (exec), proceed immediately
	// since the client→server goroutine may be blocked on stdin that never arrives.
	select {
	case err := <-clientToServerDone:
		if err != nil && err != io.EOF {
			log.Debug().Err(err).Str("sessionID", sessionID).Msg("client→server proxy error")
		}
		select {
		case err := <-serverToClientDone:
			if err != nil && err != io.EOF {
				log.Debug().Err(err).Str("sessionID", sessionID).Msg("server→client proxy error")
			}
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
		}
	case err := <-serverToClientDone:
		if err != nil && err != io.EOF {
			log.Debug().Err(err).Str("sessionID", sessionID).Msg("server→client proxy error")
		}
	case <-ctx.Done():
		log.Info().Str("sessionID", sessionID).Msg("Channel cancelled by context")
	}

	// Brief window for exit-status to be forwarded before channel teardown.
	select {
	case <-serverReqDone:
	case <-time.After(3 * time.Second):
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

					// Check exec command against blocked patterns
					if p.matchBlockedCommand(command) {
						log.Warn().
							Str("sessionID", sessionID).
							Str("command", command).
							Msg("Blocked SSH exec command")

						// Log the blocked exec to session recording
						blockedEvent := chState.textEvent(session.SessionEventInput, session.SessionChannelExec,
							fmt.Sprintf("$ %s\n[BLOCKED] Command not permitted", command))
						if err := p.config.SessionLogger.LogSessionEvent(blockedEvent); err != nil {
							log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to log blocked exec command")
						}

						if req.WantReply {
							req.Reply(false, nil)
						}
						continue
					}

					// Determine the type of operation
					isSCP := strings.HasPrefix(command, "scp ")
					chState.mutex.Lock()
					if isSCP {
						// Mark this channel as binary so we don't log the raw file data
						chState.isBinarySession = true
						chState.channelType = session.SessionChannelSFTP // SCP is file transfer
					} else {
						chState.channelType = session.SessionChannelExec
					}
					chState.mutex.Unlock()

					log.Info().
						Str("sessionID", sessionID).
						Str("command", command).
						Msg("SSH exec command")

					// Log the exec command to the session recording
					var logMessage string
					var channelType session.SessionChannelType
					if isSCP {
						channelType = session.SessionChannelSFTP
						// Parse SCP command for more readable logging
						// scp -t /path = receiving file TO server
						// scp -f /path = sending file FROM server
						if strings.Contains(command, " -t ") {
							path := extractSCPPath(command)
							logMessage = fmt.Sprintf("Uploaded file: %s", path)
						} else if strings.Contains(command, " -f ") {
							path := extractSCPPath(command)
							logMessage = fmt.Sprintf("Downloaded file: %s", path)
						} else {
							logMessage = fmt.Sprintf("$ %s", command)
						}
					} else {
						channelType = session.SessionChannelExec
						logMessage = fmt.Sprintf("$ %s", command)
					}

					event := chState.textEvent(session.SessionEventInput, channelType, logMessage)
					if err := p.config.SessionLogger.LogSessionEvent(event); err != nil {
						log.Error().Err(err).
							Str("sessionID", sessionID).
							Str("command", command).
							Msg("Failed to log exec command to session recording")
					}
				}
			}
		case "shell":
			chState.mutex.Lock()
			chState.channelType = session.SessionChannelShell
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
						chState.channelType = session.SessionChannelSFTP
						chState.isBinarySession = true
						chState.sftpParser = NewSFTPParser()
						chState.mutex.Unlock()

						event := chState.textEvent(session.SessionEventInput, session.SessionChannelSFTP, "File transfer session started")
						if err := p.config.SessionLogger.LogSessionEvent(event); err != nil {
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

	// Flush any remaining buffers on exit
	defer func() {
		if logInput {
			p.flushInputBuffer(sessionID, chState)
			p.flushPendingEcho(sessionID, chState)
		}
		if !logInput {
			p.flushOutputBuffer(sessionID, chState)
		}
	}()

	for {
		n, err := src.Read(buf)
		if n > 0 {
			if p.config.OnActivity != nil {
				p.config.OnActivity()
			}

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
					logMsg := FormatOperation(op)
					event := chState.textEvent(session.SessionEventInput, session.SessionChannelSFTP, logMsg)
					if err := p.config.SessionLogger.LogSessionEvent(event); err != nil {
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
					p.bufferInput(buf[:n], sessionID, channelType, chState)
				} else {
					p.bufferOutput(buf[:n], sessionID, channelType, chState)
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
func (p *SSHProxy) bufferInput(data []byte, sessionID string, channelType session.SessionChannelType, chState *channelState) {
	chState.inputMutex.Lock()
	defer chState.inputMutex.Unlock()

	chState.inputChannelType = channelType
	typedThisRead := false

	for _, b := range data {
		if chState.inputScanner.consumed(b) {
			continue
		}

		switch b {
		case 0x7F, 0x08: // DEL (backspace on most terminals) or BS
			if len(chState.inputBuffer) > 0 {
				chState.inputBuffer = chState.inputBuffer[:len(chState.inputBuffer)-1]
			}
		case 0x03: // Ctrl+C - cancel current input
			chState.inputBuffer = chState.inputBuffer[:0]
		case 0x15: // Ctrl+U - clear line
			chState.inputBuffer = chState.inputBuffer[:0]
		case 0x17: // Ctrl+W - delete previous word
			// Skip trailing spaces
			for len(chState.inputBuffer) > 0 && chState.inputBuffer[len(chState.inputBuffer)-1] == ' ' {
				chState.inputBuffer = chState.inputBuffer[:len(chState.inputBuffer)-1]
			}
			// Delete until next space or start
			for len(chState.inputBuffer) > 0 && chState.inputBuffer[len(chState.inputBuffer)-1] != ' ' {
				chState.inputBuffer = chState.inputBuffer[:len(chState.inputBuffer)-1]
			}
		case 0x0D, 0x0A: // CR or LF - flush the buffer
			p.flushInputBufferUnsafe(sessionID, chState, typedThisRead)
		default:
			// Only buffer printable characters and tab
			if b >= 0x20 || b == 0x09 {
				if len(chState.inputBuffer) == 0 {
					chState.echoBaseline = int(chState.outputPending.Load())
				}
				chState.inputBuffer = append(chState.inputBuffer, b)
				typedThisRead = true
			}
			// Safety: flush if buffer gets too large
			if len(chState.inputBuffer) >= 1024 {
				p.flushInputBufferUnsafe(sessionID, chState, typedThisRead)
			}
		}
	}
}

// flushInputBuffer flushes the input buffer with locking
func (p *SSHProxy) flushInputBuffer(sessionID string, chState *channelState) {
	chState.inputMutex.Lock()
	defer chState.inputMutex.Unlock()
	p.flushInputBufferUnsafe(sessionID, chState, false)
}

// flushInputBufferUnsafe records the buffered command (caller must hold the lock).
// pasted means the command and its Enter arrived in one read, so nothing echoed yet.
func (p *SSHProxy) flushInputBufferUnsafe(sessionID string, chState *channelState, pasted bool) {
	if len(chState.inputBuffer) == 0 {
		return
	}

	command := string(chState.inputBuffer)
	chState.inputBuffer = chState.inputBuffer[:0]
	channel := chState.inputChannelType

	if channel != session.SessionChannelShell {
		p.logInputCommand(sessionID, chState.textEvent(session.SessionEventInput, channel, command))
		return
	}

	onScreen := int(chState.outputPending.Load())

	// Nothing echoed means nothing will end the prompt's line either, so commit it
	// here rather than let the next command's prompt land on the same line.
	switch {
	case onScreen > chState.echoBaseline:
		// Echoed while typing, so that line is the record.
	case pasted:
		// Delivered ahead of any echo; the next committed line decides.
		chState.pendingEcho.hold(command, channel, onScreen)
	default:
		p.flushOutputBuffer(sessionID, chState)
		p.logInputCommand(sessionID, chState.textEvent(session.SessionEventInput, channel, command))
	}
}

// flushPendingEcho records a held command that the shell never echoed back
func (p *SSHProxy) flushPendingEcho(sessionID string, chState *channelState) {
	if event, ok := chState.pendingEcho.take(); ok {
		p.logInputCommand(sessionID, event)
	}
}

func (p *SSHProxy) logInputCommand(sessionID string, event session.SessionEvent) {
	if err := p.config.SessionLogger.LogSessionEvent(event); err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Str("eventType", string(session.SessionEventInput)).
			Msg("Failed to log terminal event")
	}
}

// bufferOutput renders the output stream and logs one event per displayed line
func (p *SSHProxy) bufferOutput(data []byte, sessionID string, channelType session.SessionChannelType, chState *channelState) {
	chState.outputMutex.Lock()
	defer chState.outputMutex.Unlock()

	chState.outputChannelType = channelType
	p.logOutputLines(sessionID, chState, chState.outputParser.Feed(data))

	// Read without a lock by the input goroutine, which must not stall behind the
	// session logger's fsync just to note where a command started.
	chState.outputPending.Store(int64(chState.outputParser.PendingLen()))
}

// flushOutputBuffer commits a partially rendered line
func (p *SSHProxy) flushOutputBuffer(sessionID string, chState *channelState) {
	chState.outputMutex.Lock()
	defer chState.outputMutex.Unlock()
	p.logOutputLines(sessionID, chState, chState.outputParser.Flush())
	chState.outputPending.Store(0)
}

// logOutputLines writes one output event per rendered line (caller must hold outputMutex)
func (p *SSHProxy) logOutputLines(sessionID string, chState *channelState, lines []string) {
	for _, line := range lines {
		event := chState.textEvent(session.SessionEventOutput, chState.outputChannelType, line)
		if err := p.config.SessionLogger.LogSessionEvent(event); err != nil {
			log.Error().Err(err).
				Str("sessionID", sessionID).
				Str("eventType", string(session.SessionEventOutput)).
				Msg("Failed to log terminal event")
		}

		if unechoed, ok := chState.pendingEcho.settle(line); ok {
			p.logInputCommand(sessionID, unechoed)
		}
	}
}

// matchBlockedCommand checks if a command matches any blocked pattern.
func (p *SSHProxy) matchBlockedCommand(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" || len(p.config.BlockedCommandPatterns) == 0 {
		return false
	}
	for _, pattern := range p.config.BlockedCommandPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// proxyClientToServerWithBlocking proxies client→server data with command blocking.
// It forwards all bytes immediately except Enter (CR/LF), which is checked against
// blocked patterns before forwarding. If blocked, Enter is suppressed, a message is
// sent to the client, and Ctrl+U/Ctrl+C clear the server's input.
func (p *SSHProxy) proxyClientToServerWithBlocking(src io.Reader, dst io.Writer, clientWriter io.Writer, sessionID string, chState *channelState) error {
	buf := make([]byte, 32*1024)

	log.Debug().
		Str("sessionID", sessionID).
		Int("numPatterns", len(p.config.BlockedCommandPatterns)).
		Msg("Command blocking active for client→server proxy")

	defer func() {
		p.flushInputBuffer(sessionID, chState)
		p.flushPendingEcho(sessionID, chState)
	}()

	for {
		n, err := src.Read(buf)
		if n > 0 {
			if p.config.OnActivity != nil {
				p.config.OnActivity()
			}

			chState.mutex.Lock()
			isBinary := chState.isBinarySession
			sftpParser := chState.sftpParser
			channelType := chState.channelType
			chState.mutex.Unlock()

			if isBinary {
				// Binary SFTP/SCP session — no command blocking, log file operations
				if sftpParser != nil {
					operations := sftpParser.Parse(buf[:n])
					for _, op := range operations {
						logMsg := FormatOperation(op)
						event := chState.textEvent(session.SessionEventInput, session.SessionChannelSFTP, logMsg)
						if logErr := p.config.SessionLogger.LogSessionEvent(event); logErr != nil {
							log.Error().Err(logErr).
								Str("sessionID", sessionID).
								Str("operation", op.Type).
								Str("path", op.Path).
								Msg("Failed to log SFTP operation")
						}
					}
				}
				if written, writeErr := dst.Write(buf[:n]); writeErr != nil {
					return writeErr
				} else if written != n {
					return io.ErrShortWrite
				}
			} else {
				// Interactive/exec session — check for blocked commands at Enter
				segStart := 0
				for i := 0; i < n; i++ {
					b := buf[i]
					if b == 0x0D || b == 0x0A {
						// Forward and log everything before this CR/LF
						if i > segStart {
							segment := buf[segStart:i]
							p.bufferInput(segment, sessionID, channelType, chState)
							if _, writeErr := dst.Write(segment); writeErr != nil {
								return writeErr
							}
						}

						// Check accumulated command against blocked patterns
						chState.inputMutex.Lock()
						command := string(chState.inputBuffer)
						chState.inputMutex.Unlock()

						if p.matchBlockedCommand(command) {
							// Commit the echoed line before the notice so they read in order.
							p.flushInputBuffer(sessionID, chState)
							p.flushOutputBuffer(sessionID, chState)

							// Send error message to client (red text)
							blockedMsg := "\r\n\033[31m[BLOCKED] Command not permitted\033[0m\r\n"
							clientWriter.Write([]byte(blockedMsg))

							// Log the blocked message as output so it appears in session replay
							blockedEvent := chState.textEvent(session.SessionEventOutput, channelType, "[BLOCKED] Command not permitted")
							if logErr := p.config.SessionLogger.LogSessionEvent(blockedEvent); logErr != nil {
								log.Error().Err(logErr).Str("sessionID", sessionID).Msg("Failed to log blocked command event")
							}

							// Clear server's pending input and get a fresh prompt (synthetic, bypass buffers)
							dst.Write([]byte{0x15}) // Ctrl+U — clear line
							dst.Write([]byte{0x03}) // Ctrl+C — fresh prompt

							log.Warn().
								Str("sessionID", sessionID).
								Str("command", command).
								Msg("Blocked SSH command")
						} else {
							// Allowed — forward the CR/LF through normal path
							p.bufferInput([]byte{b}, sessionID, channelType, chState)
							if _, writeErr := dst.Write([]byte{b}); writeErr != nil {
								return writeErr
							}
						}

						segStart = i + 1
					}
				}

				// Forward remaining segment after last CR/LF (or the entire chunk if no CR/LF)
				if segStart < n {
					segment := buf[segStart:n]
					p.bufferInput(segment, sessionID, channelType, chState)
					if _, writeErr := dst.Write(segment); writeErr != nil {
						return writeErr
					}
				}
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
