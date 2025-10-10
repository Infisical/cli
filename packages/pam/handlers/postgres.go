package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	session "github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/pbkdf2" // TODO: Remove this once we update to go 1.25.1 or later where it's already in the standard library
)

const (
	// MaxDataRowsToStore limits the number of data rows stored per query for storage efficiency
	MaxDataRowsToStore = 10
)

type PostgresProxyConfig struct {
	TargetAddr     string
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	SessionLogger  session.SessionLogger
}

type PostgresProxy struct {
	config             PostgresProxyConfig
	mutex              sync.Mutex
	pendingRequests    map[string]*PendingRequest
	preparedStatements map[string]string
	activePortal       string
}

type PendingRequest struct {
	Timestamp      time.Time
	Request        string
	RequestType    string
	DataRows       []map[string]interface{}
	RowDescription []string
	RowCount       int
	PreparedSQL    string
	BoundParams    []string
	PortalName     string
}

func NewPostgresProxy(config PostgresProxyConfig) (*PostgresProxy, error) {
	return &PostgresProxy{
		config:             config,
		pendingRequests:    make(map[string]*PendingRequest),
		preparedStatements: make(map[string]string),
	}, nil
}

// HandleConnection handles a single client connection using the provided connection
func (p *PostgresProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
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
		Msg("New PostgreSQL connection for PAM session")

	// Connect to real PostgreSQL server
	serverConn, err := p.connectToServer()
	if err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Msg("Failed to connect to PostgreSQL server")
		return fmt.Errorf("failed to connect to PostgreSQL server: %w", err)
	}
	defer serverConn.Close()

	// Create protocol frontends/backends
	clientBackend := pgproto3.NewBackend(clientConn, clientConn)
	serverFrontend := pgproto3.NewFrontend(serverConn, serverConn)

	// Handle startup and authentication with credential injection
	if err := p.handleStartup(clientConn, clientBackend, serverFrontend); err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Msg("Startup failed")
		return fmt.Errorf("startup failed: %w", err)
	}

	// Proxy messages bidirectionally
	errChan := make(chan error, 2)

	go p.proxyClientToServer(clientBackend, serverFrontend, errChan)
	go p.proxyServerToClient(serverFrontend, clientBackend, errChan)

	// Wait for either direction to error/close or context cancellation
	select {
	case err = <-errChan:
		if err != nil && err != io.EOF {
			// Check if it's an unexpected EOF (connection terminated abruptly)
			if err.Error() == "unexpected EOF" {
				log.Debug().Err(err).
					Str("sessionID", sessionID).
					Msg("Connection terminated unexpectedly")
			} else {
				log.Error().Err(err).
					Str("sessionID", sessionID).
					Msg("Connection error")
			}
		}
	case <-ctx.Done():
		log.Info().
			Str("sessionID", sessionID).
			Msg("Connection cancelled by context")
		err = ctx.Err()
	}

	log.Info().
		Str("sessionID", sessionID).
		Msg("Connection closed")

	// Clean up any pending requests and write them to file
	p.cleanupPendingRequests()

	return err
}

func (p *PostgresProxy) connectToServer() (net.Conn, error) {
	serverConn, err := net.Dial("tcp", p.config.TargetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial server: %w", err)
	}

	sslRequest := &pgproto3.SSLRequest{}
	sslRequestBytes, _ := sslRequest.Encode(nil)

	_, err = serverConn.Write(sslRequestBytes)
	if err != nil {
		serverConn.Close()
		return nil, fmt.Errorf("failed to send SSL request: %w", err)
	}

	// Read server's response (single byte: 'S' for SSL supported, 'N' for not supported)
	response := make([]byte, 1)
	_, err = serverConn.Read(response)
	if err != nil {
		serverConn.Close()
		return nil, fmt.Errorf("failed to read SSL response: %w", err)
	}

	if response[0] == 'S' {
		tlsConn := tls.Client(serverConn, p.config.TLSConfig)
		err = tlsConn.Handshake()
		if err != nil {
			serverConn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		log.Info().
			Str("sessionID", p.config.SessionID).
			Msg("Successfully established TLS connection to PostgreSQL server")
		return tlsConn, nil

	} else if response[0] == 'N' {
		if p.config.EnableTLS {
			return nil, fmt.Errorf("PostgreSQL server does not support SSL, but TLS was requested")
		}

		log.Info().
			Str("sessionID", p.config.SessionID).
			Msg("Connected to PostgreSQL server without TLS")

		return serverConn, nil
	}

	serverConn.Close()
	return nil, fmt.Errorf("unexpected SSL response from server: %c", response[0])
}

func (p *PostgresProxy) handleStartup(clientConn net.Conn, clientBackend *pgproto3.Backend, serverFrontend *pgproto3.Frontend) error {
	var receivedSSLRequest bool
	var receivedGSSEncRequest bool

	// Loop to handle SSL/GSS negotiation before actual startup
	for {
		startupMsg, err := clientBackend.ReceiveStartupMessage()
		if err != nil {
			return fmt.Errorf("receive startup: %w", err)
		}

		log.Debug().
			Str("sessionID", p.config.SessionID).
			Str("msgType", fmt.Sprintf("%T", startupMsg)).
			Msg("← CLIENT")

		switch msg := startupMsg.(type) {
		case *pgproto3.SSLRequest:
			if receivedSSLRequest {
				return fmt.Errorf("received duplicate SSLRequest")
			}
			receivedSSLRequest = true

			// Always deny SSL from client to proxy (we want plain text here)
			// SSL/TLS is handled separately for proxy-to-server connection
			_, err := clientConn.Write([]byte("N"))
			if err != nil {
				return fmt.Errorf("send SSL response: %w", err)
			}
			log.Debug().Str("sessionID", p.config.SessionID).Msg("→ CLIENT: SSLResponse (denied - client-to-proxy is plain text)")
			continue

		case *pgproto3.GSSEncRequest:
			if receivedGSSEncRequest {
				return fmt.Errorf("received duplicate GSSEncRequest")
			}
			receivedGSSEncRequest = true

			// Send 'N' to deny GSS encryption
			_, err := clientConn.Write([]byte("N"))
			if err != nil {
				return fmt.Errorf("send GSS response: %w", err)
			}
			log.Debug().Str("sessionID", p.config.SessionID).Msg("→ CLIENT: GSSEncResponse (denied)")
			continue

		case *pgproto3.StartupMessage:
			msg.Parameters["user"] = p.config.InjectUsername
			msg.Parameters["database"] = p.config.InjectDatabase

			// Forward modified startup to server
			log.Debug().Str("sessionID", p.config.SessionID).Interface("params", msg.Parameters).Msg("→ SERVER: StartupMessage")
			serverFrontend.Send(msg)
			err := serverFrontend.Flush()
			if err != nil {
				return fmt.Errorf("failed to flush startup message: %w", err)
			}

			// Handle authentication exchange
			return p.handleAuthentication(clientBackend, serverFrontend)

		case *pgproto3.CancelRequest:
			log.Debug().Str("sessionID", p.config.SessionID).Uint32("pid", msg.ProcessID).Uint32("secret", msg.SecretKey).Msg("← CLIENT: CancelRequest")
			serverFrontend.Send(msg)
			err := serverFrontend.Flush()
			if err != nil {
				return fmt.Errorf("failed to flush cancel request: %w", err)
			}
			return nil

		default:
			return fmt.Errorf("unexpected startup message type: %T", msg)
		}
	}
}

func (p *PostgresProxy) handleAuthentication(clientBackend *pgproto3.Backend, serverFrontend *pgproto3.Frontend) error {
	for {
		// Receive authentication request from server
		msg, err := serverFrontend.Receive()
		if err != nil {
			return fmt.Errorf("receive auth message from server: %w", err)
		}

		log.Debug().Str("sessionID", p.config.SessionID).Str("msgType", fmt.Sprintf("%T", msg)).Msg("← SERVER")

		switch authMsg := msg.(type) {
		case *pgproto3.AuthenticationOk:
			// Authentication successful - forward to client and we're done
			log.Info().Str("sessionID", p.config.SessionID).Msg("✓ Authentication successful")
			clientBackend.Send(authMsg)
			err = clientBackend.Flush()
			if err != nil {
				return fmt.Errorf("failed to flush auth ok: %w", err)
			}
			return nil

		case *pgproto3.AuthenticationCleartextPassword:
			// Server wants cleartext password
			// The proxy will handle this authentication using injected credentials
			// The client will NOT participate in the password exchange
			return p.handleCleartextPasswordAsProxy(clientBackend, serverFrontend)

		case *pgproto3.AuthenticationMD5Password:
			// Server wants MD5 encrypted password
			// The proxy will handle this authentication using injected credentials
			// The client will NOT participate in the password exchange
			return p.handleMD5PasswordAsProxy(clientBackend, serverFrontend, authMsg)

		case *pgproto3.AuthenticationSASL:
			// Server wants SASL authentication (SCRAM-SHA-256)
			// The proxy will handle this authentication using injected credentials
			// The client will NOT participate in the SASL exchange
			return p.handleSASLAuthenticationAsProxy(clientBackend, serverFrontend, authMsg)

		case *pgproto3.ErrorResponse:
			// Authentication error - forward to client
			log.Error().Str("sessionID", p.config.SessionID).Str("error", authMsg.Message).Msg("→ CLIENT: ErrorResponse")
			clientBackend.Send(authMsg)
			err = clientBackend.Flush()
			if err != nil {
				return fmt.Errorf("failed to flush error response: %w", err)
			}
			return fmt.Errorf("authentication failed: %s", authMsg.Message)

		case *pgproto3.ParameterStatus:
			// Server sending parameter status during auth - forward to client
			log.Debug().Str("sessionID", p.config.SessionID).Str("name", authMsg.Name).Str("value", authMsg.Value).Msg("→ CLIENT: ParameterStatus")
			clientBackend.Send(authMsg)
			err = clientBackend.Flush()
			if err != nil {
				return fmt.Errorf("failed to flush parameter status: %w", err)
			}
			// Continue authentication loop

		case *pgproto3.ReadyForQuery:
			// Server is ready - authentication complete
			log.Debug().Str("sessionID", p.config.SessionID).Str("status", string(authMsg.TxStatus)).Msg("→ CLIENT: ReadyForQuery")
			clientBackend.Send(authMsg)
			err = clientBackend.Flush()
			if err != nil {
				return fmt.Errorf("failed to flush ready for query: %w", err)
			}
			return nil

		default:
			// Unknown auth message - forward as-is and continue
			log.Debug().Str("sessionID", p.config.SessionID).Str("msgType", fmt.Sprintf("%T", authMsg)).Msg("→ CLIENT: Unknown auth message")
			clientBackend.Send(authMsg)
			err = clientBackend.Flush()
			if err != nil {
				return fmt.Errorf("failed to flush unknown auth message: %w", err)
			}
		}
	}
}

func (p *PostgresProxy) handlePasswordResponse(clientBackend *pgproto3.Backend, serverFrontend *pgproto3.Frontend) error {
	// Receive password message from client
	clientMsg, err := clientBackend.Receive()
	if err != nil {
		return fmt.Errorf("receive password from client: %w", err)
	}

	log.Debug().Str("sessionID", p.config.SessionID).Str("msgType", fmt.Sprintf("%T", clientMsg)).Msg("← CLIENT")

	switch passwordMsg := clientMsg.(type) {
	case *pgproto3.PasswordMessage:
		passwordMsg.Password = p.config.InjectPassword
		serverFrontend.Send(passwordMsg)
		err = serverFrontend.Flush()
		if err != nil {
			return fmt.Errorf("failed to flush password message: %w", err)
		}

		return p.handleAuthentication(clientBackend, serverFrontend)

	default:
		return fmt.Errorf("expected PasswordMessage from client, got %T", clientMsg)
	}
}

// SCRAM-SHA-256 authentication handler - proxy authenticates to server using injected credentials
func (p *PostgresProxy) handleSASLAuthenticationAsProxy(clientBackend *pgproto3.Backend, serverFrontend *pgproto3.Frontend, authSASL *pgproto3.AuthenticationSASL) error {
	// Verify the server supports SCRAM-SHA-256
	supportsSCRAM := false
	for _, mechanism := range authSASL.AuthMechanisms {
		if mechanism == "SCRAM-SHA-256" {
			supportsSCRAM = true
			break
		}
	}

	if !supportsSCRAM {
		return fmt.Errorf("server does not support SCRAM-SHA-256")
	}

	// Step 1: Generate client nonce and create initial message
	clientNonce, err := session.GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate client nonce: %w", err)
	}

	username := p.config.InjectUsername

	// Create client-first-message: n,,n=username,r=clientNonce
	clientFirstMessageBare := fmt.Sprintf("n=%s,r=%s", username, clientNonce)
	clientFirstMessage := fmt.Sprintf("n,,%s", clientFirstMessageBare)

	// Send SASLInitialResponse
	initialResponse := &pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256",
		Data:          []byte(clientFirstMessage),
	}

	log.Debug().Str("sessionID", p.config.SessionID).Msg("→ SERVER: SASLInitialResponse with SCRAM-SHA-256")
	serverFrontend.Send(initialResponse)
	err = serverFrontend.Flush()
	if err != nil {
		return fmt.Errorf("failed to send SASL initial response: %w", err)
	}

	// Step 2: Receive server's first message
	serverMsg, err := serverFrontend.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive server SASL response: %w", err)
	}

	saslContinue, ok := serverMsg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return fmt.Errorf("expected AuthenticationSASLContinue, got %T", serverMsg)
	}

	log.Debug().Str("sessionID", p.config.SessionID).Msg("← SERVER: AuthenticationSASLContinue")

	// Parse server-first-message: r=clientNonce+serverNonce,s=salt,i=iterations
	serverFirstMessage := string(saslContinue.Data)
	serverNonce, salt, iterations, err := p.parseServerFirstMessage(serverFirstMessage, clientNonce)
	if err != nil {
		return fmt.Errorf("failed to parse server first message: %w", err)
	}

	log.Debug().Str("sessionID", p.config.SessionID).Int("iterations", iterations).Msg("SCRAM parameters")

	// Step 3: Calculate client proof
	password := p.config.InjectPassword
	clientFinalMessageWithoutProof := fmt.Sprintf("c=biws,r=%s", serverNonce) // biws = base64("n,,")

	saltedPassword := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	clientKey := session.HmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := session.SHA256Hash(clientKey)

	authMessage := fmt.Sprintf("%s,%s,%s", clientFirstMessageBare, serverFirstMessage, clientFinalMessageWithoutProof)
	clientSignature := session.HmacSHA256(storedKey, []byte(authMessage))

	clientProof := make([]byte, len(clientKey))
	for i := range clientKey {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}

	clientFinalMessage := fmt.Sprintf("%s,p=%s", clientFinalMessageWithoutProof, base64.StdEncoding.EncodeToString(clientProof))

	// Send SASLResponse
	saslResponse := &pgproto3.SASLResponse{
		Data: []byte(clientFinalMessage),
	}

	log.Debug().Str("sessionID", p.config.SessionID).Msg("→ SERVER: SASLResponse with client proof")
	serverFrontend.Send(saslResponse)
	err = serverFrontend.Flush()
	if err != nil {
		return fmt.Errorf("failed to send SASL response: %w", err)
	}

	// Step 4: Receive server's final message
	serverMsg, err = serverFrontend.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive server SASL final: %w", err)
	}

	switch finalMsg := serverMsg.(type) {
	case *pgproto3.AuthenticationSASLFinal:
		log.Debug().Str("sessionID", p.config.SessionID).Msg("← SERVER: AuthenticationSASLFinal")

		// Verify server signature
		serverFinalMessage := string(finalMsg.Data)
		if !p.verifyServerSignature(serverFinalMessage, saltedPassword, authMessage) {
			return fmt.Errorf("server signature verification failed")
		}

		log.Debug().Str("sessionID", p.config.SessionID).Msg("Server signature verified successfully")

		// Wait for AuthenticationOk
		serverMsg, err = serverFrontend.Receive()
		if err != nil {
			return fmt.Errorf("failed to receive auth ok: %w", err)
		}

		authOk, ok := serverMsg.(*pgproto3.AuthenticationOk)
		if !ok {
			return fmt.Errorf("expected AuthenticationOk after SASL, got %T", serverMsg)
		}

		// Now send AuthenticationOk to client (client never participated in SASL)
		clientBackend.Send(authOk)
		err = clientBackend.Flush()
		if err != nil {
			return fmt.Errorf("failed to send auth ok to client: %w", err)
		}

		return nil

	case *pgproto3.ErrorResponse:
		log.Error().Str("sessionID", p.config.SessionID).Str("error", finalMsg.Message).Msg("← SERVER: SCRAM authentication failed")
		return fmt.Errorf("SCRAM authentication failed: %s", finalMsg.Message)

	default:
		return fmt.Errorf("unexpected message after SASL response: %T", finalMsg)
	}
}

// Helper functions for SCRAM-SHA-256

func (p *PostgresProxy) parseServerFirstMessage(serverFirstMessage, clientNonce string) (serverNonce string, salt []byte, iterations int, err error) {
	parts := strings.Split(serverFirstMessage, ",")
	if len(parts) != 3 {
		return "", nil, 0, fmt.Errorf("invalid server first message format")
	}

	// Parse r=nonce
	if !strings.HasPrefix(parts[0], "r=") {
		return "", nil, 0, fmt.Errorf("missing nonce in server first message")
	}
	serverNonce = parts[0][2:]
	if !strings.HasPrefix(serverNonce, clientNonce) {
		return "", nil, 0, fmt.Errorf("server nonce does not start with client nonce")
	}

	// Parse s=salt
	if !strings.HasPrefix(parts[1], "s=") {
		return "", nil, 0, fmt.Errorf("missing salt in server first message")
	}
	salt, err = base64.StdEncoding.DecodeString(parts[1][2:])
	if err != nil {
		return "", nil, 0, fmt.Errorf("invalid salt encoding: %w", err)
	}

	// Parse i=iterations
	if !strings.HasPrefix(parts[2], "i=") {
		return "", nil, 0, fmt.Errorf("missing iterations in server first message")
	}
	iterations, err = strconv.Atoi(parts[2][2:])
	if err != nil {
		return "", nil, 0, fmt.Errorf("invalid iterations: %w", err)
	}

	return serverNonce, salt, iterations, nil
}

func (p *PostgresProxy) verifyServerSignature(serverFinalMessage string, saltedPassword []byte, authMessage string) bool {
	// Parse v=serverSignature
	if !strings.HasPrefix(serverFinalMessage, "v=") {
		return false
	}

	receivedSignature, err := base64.StdEncoding.DecodeString(serverFinalMessage[2:])
	if err != nil {
		return false
	}

	// Calculate expected server signature
	serverKey := session.HmacSHA256(saltedPassword, []byte("Server Key"))
	expectedSignature := session.HmacSHA256(serverKey, []byte(authMessage))

	// Compare signatures
	return hmac.Equal(receivedSignature, expectedSignature)
}

func (p *PostgresProxy) handleCleartextPasswordAsProxy(clientBackend *pgproto3.Backend, serverFrontend *pgproto3.Frontend) error {
	// Send the injected password directly to the server
	passwordMsg := &pgproto3.PasswordMessage{
		Password: p.config.InjectPassword,
	}

	log.Debug().Str("sessionID", p.config.SessionID).Msg("→ SERVER: PasswordMessage with injected credentials")
	serverFrontend.Send(passwordMsg)
	err := serverFrontend.Flush()
	if err != nil {
		return fmt.Errorf("failed to send password to server: %w", err)
	}

	// Wait for server response
	serverMsg, err := serverFrontend.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive server response: %w", err)
	}

	switch responseMsg := serverMsg.(type) {
	case *pgproto3.AuthenticationOk:
		// Send AuthenticationOk to client (client never participated in password exchange)
		clientBackend.Send(responseMsg)
		err = clientBackend.Flush()
		if err != nil {
			return fmt.Errorf("failed to send auth ok to client: %w", err)
		}
		return nil

	case *pgproto3.ErrorResponse:
		log.Error().Str("sessionID", p.config.SessionID).Str("error", responseMsg.Message).Msg("← SERVER: Cleartext password authentication failed")
		// Forward error to client
		clientBackend.Send(responseMsg)
		err = clientBackend.Flush()
		if err != nil {
			return fmt.Errorf("failed to send error to client: %w", err)
		}
		return fmt.Errorf("cleartext password authentication failed: %s", responseMsg.Message)

	default:
		return fmt.Errorf("unexpected response after cleartext password: %T", responseMsg)
	}
}

func (p *PostgresProxy) handleMD5PasswordAsProxy(clientBackend *pgproto3.Backend, serverFrontend *pgproto3.Frontend, authMD5 *pgproto3.AuthenticationMD5Password) error {
	// Calculate MD5 hash: md5(md5(password + username) + salt)
	username := p.config.InjectUsername
	password := p.config.InjectPassword
	salt := authMD5.Salt

	// First hash: md5(password + username)
	firstHash := md5.Sum([]byte(password + username))
	firstHashHex := fmt.Sprintf("%x", firstHash)

	// Second hash: md5(firstHashHex + salt)
	secondInput := append([]byte(firstHashHex), salt[:]...)
	secondHash := md5.Sum(secondInput)
	finalHash := fmt.Sprintf("md5%x", secondHash)

	// Send the MD5 hashed password to the server
	passwordMsg := &pgproto3.PasswordMessage{
		Password: finalHash,
	}

	log.Debug().Str("sessionID", p.config.SessionID).Msg("→ SERVER: PasswordMessage with MD5 hashed injected credentials")
	serverFrontend.Send(passwordMsg)
	err := serverFrontend.Flush()
	if err != nil {
		return fmt.Errorf("failed to send MD5 password to server: %w", err)
	}

	// Wait for server response
	serverMsg, err := serverFrontend.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive server response: %w", err)
	}

	switch responseMsg := serverMsg.(type) {
	case *pgproto3.AuthenticationOk:
		// Send AuthenticationOk to client (client never participated in password exchange)
		clientBackend.Send(responseMsg)
		err = clientBackend.Flush()
		if err != nil {
			return fmt.Errorf("failed to send auth ok to client: %w", err)
		}
		return nil

	case *pgproto3.ErrorResponse:
		log.Error().Str("sessionID", p.config.SessionID).Str("error", responseMsg.Message).Msg("← SERVER: MD5 password authentication failed")
		// Forward error to client
		clientBackend.Send(responseMsg)
		err = clientBackend.Flush()
		if err != nil {
			return fmt.Errorf("failed to send error to client: %w", err)
		}
		return fmt.Errorf("MD5 password authentication failed: %s", responseMsg.Message)

	default:
		return fmt.Errorf("unexpected response after MD5 password: %T", responseMsg)
	}
}

func (p *PostgresProxy) proxyClientToServer(clientBackend *pgproto3.Backend, serverFrontend *pgproto3.Frontend, errChan chan error) {
	for {
		msg, err := clientBackend.Receive()
		if err != nil {
			errChan <- err
			return
		}

		p.trackClientMessage(msg)

		serverFrontend.Send(msg)
		err = serverFrontend.Flush()
		if err != nil {
			errChan <- err
			return
		}
	}
}

func (p *PostgresProxy) proxyServerToClient(serverFrontend *pgproto3.Frontend, clientBackend *pgproto3.Backend, errChan chan error) {
	for {
		msg, err := serverFrontend.Receive()
		if err != nil {
			errChan <- err
			return
		}

		p.trackServerMessage(msg)

		clientBackend.Send(msg)
		err = clientBackend.Flush()
		if err != nil {
			errChan <- err
			return
		}
	}
}

func (p *PostgresProxy) trackClientMessage(msg pgproto3.FrontendMessage) {
	switch m := msg.(type) {
	case *pgproto3.Query:
		// Simple query - track immediately
		requestKey := fmt.Sprintf("query-%d", time.Now().UnixNano())
		log.Debug().Str("sessionID", p.config.SessionID).Str("query", m.String).Msg("← CLIENT Query")

		p.mutex.Lock()
		p.pendingRequests[requestKey] = &PendingRequest{
			Timestamp:   time.Now(),
			Request:     m.String,
			RequestType: "Query",
		}
		p.mutex.Unlock()

	case *pgproto3.Parse:
		// Store prepared statement SQL for later use
		log.Debug().Str("sessionID", p.config.SessionID).Str("name", m.Name).Str("query", m.Query).Msg("← CLIENT Parse")

		p.mutex.Lock()
		p.preparedStatements[m.Name] = m.Query
		p.mutex.Unlock()

	case *pgproto3.Bind:
		// Bind parameters to prepared statement
		log.Debug().Str("sessionID", p.config.SessionID).Str("portal", m.DestinationPortal).Str("statement", m.PreparedStatement).Int("params", len(m.Parameters)).Msg("← CLIENT Bind")

		p.mutex.Lock()
		preparedSQL := p.preparedStatements[m.PreparedStatement]

		// Convert parameters to strings for logging
		boundParams := make([]string, len(m.Parameters))
		for i, param := range m.Parameters {
			if param == nil {
				boundParams[i] = "NULL"
			} else {
				boundParams[i] = string(param)
			}
		}

		// Create a pending request for this portal that will be executed
		requestKey := fmt.Sprintf("portal-%s", m.DestinationPortal)
		p.pendingRequests[requestKey] = &PendingRequest{
			Timestamp:   time.Now(),
			Request:     p.buildExecutableSQL(preparedSQL, boundParams),
			RequestType: "PreparedStatement",
			PreparedSQL: preparedSQL,
			BoundParams: boundParams,
			PortalName:  m.DestinationPortal,
		}
		p.mutex.Unlock()

	case *pgproto3.Execute:
		// Execute the portal - mark it as active
		log.Debug().Str("sessionID", p.config.SessionID).Str("portal", m.Portal).Int("maxRows", int(m.MaxRows)).Msg("← CLIENT Execute")

		p.mutex.Lock()
		p.activePortal = m.Portal
		p.mutex.Unlock()

	case *pgproto3.Terminate:
		log.Debug().Str("sessionID", p.config.SessionID).Msg("← CLIENT Terminate")
		return // Don't track terminate messages

	default:
		log.Debug().Str("sessionID", p.config.SessionID).Str("msgType", fmt.Sprintf("%T", msg)).Msg("← CLIENT")
		return // Don't track unknown message types
	}
}

func (p *PostgresProxy) trackServerMessage(msg pgproto3.BackendMessage) {
	switch m := msg.(type) {
	case *pgproto3.RowDescription:
		// Start of query results - capture column information
		log.Debug().Str("sessionID", p.config.SessionID).Int("fields", len(m.Fields)).Msg("→ SERVER RowDescription")
		p.handleRowDescription(m)

	case *pgproto3.DataRow:
		// Data row - collect the actual data
		log.Debug().Str("sessionID", p.config.SessionID).Int("columns", len(m.Values)).Msg("→ SERVER DataRow")
		p.handleDataRow(m)

	case *pgproto3.CommandComplete:
		// End of query - finalize and record the complete response
		response := string(m.CommandTag)
		log.Debug().Str("sessionID", p.config.SessionID).Str("tag", string(m.CommandTag)).Msg("→ SERVER CommandComplete")

		// Try to match with active portal first (prepared statement), then regular queries
		if p.activePortal != "" {
			p.matchAndRecordResponseWithData("PreparedStatement", response, "CommandComplete")
		} else {
			p.matchAndRecordResponseWithData("Query", response, "CommandComplete")
		}

	case *pgproto3.ReadyForQuery:
		// Transaction/query completely finished
		response := fmt.Sprintf("ReadyForQuery: status=%c", m.TxStatus)
		log.Debug().Str("sessionID", p.config.SessionID).Str("response", response).Msg("→ SERVER")
		// ReadyForQuery usually comes after CommandComplete, so don't double-record

	case *pgproto3.ErrorResponse:
		// Query failed
		response := m.Message
		log.Debug().Str("sessionID", p.config.SessionID).Str("error", m.Message).Msg("→ SERVER ErrorResponse")

		// Clear active portal on error
		p.mutex.Lock()
		p.activePortal = ""
		p.mutex.Unlock()

		p.matchAndRecordResponseWithData("", response, "ErrorResponse")

	case *pgproto3.NoticeResponse:
		// Just a notice, don't record
		log.Debug().Str("sessionID", p.config.SessionID).Str("notice", m.Message).Msg("→ SERVER NoticeResponse")

	default:
		log.Debug().Str("sessionID", p.config.SessionID).Str("msgType", fmt.Sprintf("%T", msg)).Msg("→ SERVER")
	}
}

// Handle RowDescription - capture column names for pending queries
func (p *PostgresProxy) handleRowDescription(rowDesc *pgproto3.RowDescription) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Extract column names
	columnNames := make([]string, len(rowDesc.Fields))
	for i, field := range rowDesc.Fields {
		columnNames[i] = string(field.Name)
	}

	// Find the appropriate pending request
	var targetReq *PendingRequest

	// First, check if we have an active portal (prepared statement)
	if p.activePortal != "" {
		portalKey := fmt.Sprintf("portal-%s", p.activePortal)
		if req, exists := p.pendingRequests[portalKey]; exists {
			targetReq = req
		}
	}

	// If no active portal, find the most recent Query request
	if targetReq == nil {
		for _, req := range p.pendingRequests {
			if req.RequestType == "Query" {
				targetReq = req
				break
			}
		}
	}

	if targetReq != nil {
		targetReq.RowDescription = columnNames
		targetReq.DataRows = []map[string]interface{}{} // Initialize data rows slice
	}
}

// Handle DataRow - collect actual row data
func (p *PostgresProxy) handleDataRow(dataRow *pgproto3.DataRow) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Find the appropriate pending request
	var targetReq *PendingRequest

	// First, check if we have an active portal (prepared statement)
	if p.activePortal != "" {
		portalKey := fmt.Sprintf("portal-%s", p.activePortal)
		if req, exists := p.pendingRequests[portalKey]; exists && req.RowDescription != nil {
			targetReq = req
		}
	}

	// If no active portal, find the most recent Query request
	if targetReq == nil {
		for _, req := range p.pendingRequests {
			if req.RequestType == "Query" && req.RowDescription != nil {
				targetReq = req
				break
			}
		}
	}

	if targetReq != nil {
		// Convert raw bytes to readable values
		rowData := make(map[string]interface{})

		for i, value := range dataRow.Values {
			columnName := ""
			if i < len(targetReq.RowDescription) {
				columnName = targetReq.RowDescription[i]
			} else {
				columnName = fmt.Sprintf("column_%d", i)
			}

			if value == nil {
				rowData[columnName] = nil
			} else {
				// Convert bytes to string (PostgreSQL sends all data as text over the wire)
				rowData[columnName] = string(value)
			}
		}

		// Only store up to MaxDataRowsToStore data rows for storage efficiency
		if len(targetReq.DataRows) < MaxDataRowsToStore {
			targetReq.DataRows = append(targetReq.DataRows, rowData)
		}
		targetReq.RowCount++
	}
}

// Helper function to build executable SQL from prepared statement and parameters
func (p *PostgresProxy) buildExecutableSQL(preparedSQL string, params []string) string {
	if len(params) == 0 {
		return preparedSQL
	}

	// Replace $1, $2, etc. with actual parameter values
	executableSQL := preparedSQL
	for i, param := range params {
		placeholder := fmt.Sprintf("$%d", i+1)
		// Add quotes around non-NULL string parameters for better readability
		if param == "NULL" {
			executableSQL = strings.ReplaceAll(executableSQL, placeholder, param)
		} else {
			// Try to determine if it's a number or string
			if _, err := strconv.Atoi(param); err == nil {
				// It's a number, don't quote
				executableSQL = strings.ReplaceAll(executableSQL, placeholder, param)
			} else {
				// It's a string, quote it
				executableSQL = strings.ReplaceAll(executableSQL, placeholder, fmt.Sprintf("'%s'", strings.ReplaceAll(param, "'", "''")))
			}
		}
	}

	return executableSQL
}

// Helper function to build output string that represents what the client sees
func (p *PostgresProxy) buildOutputString(response string, responseType string, req *PendingRequest) string {
	if responseType == "ErrorResponse" {
		return fmt.Sprintf("ERROR: %s", response)
	}

	if req.RowCount > 0 && len(req.DataRows) > 0 {
		// Query returned data - include the actual data rows in the output
		outputData := map[string]interface{}{
			"command":    response,
			"total_rows": req.RowCount,
			"data_rows":  req.DataRows,
		}

		if req.RowCount > MaxDataRowsToStore {
			outputData["note"] = fmt.Sprintf("Showing first %d of %d rows", len(req.DataRows), req.RowCount)
		}

		// Convert to JSON string for the output
		if jsonBytes, err := json.Marshal(outputData); err == nil {
			return string(jsonBytes)
		} else {
			// Fallback if JSON marshaling fails
			return fmt.Sprintf("%s (returned %d rows, JSON error: %v)", response, req.RowCount, err)
		}
	} else {
		// Command without data (INSERT, UPDATE, DELETE, etc.) or no results
		return response
	}
}

// New method that includes collected data rows
func (p *PostgresProxy) matchAndRecordResponseWithData(preferredType string, response string, responseType string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Find a matching pending request
	var matchedKey string
	var matchedRequest *PendingRequest

	// First, check if we have an active portal (prepared statement)
	if p.activePortal != "" {
		portalKey := fmt.Sprintf("portal-%s", p.activePortal)
		if req, exists := p.pendingRequests[portalKey]; exists {
			matchedKey = portalKey
			matchedRequest = req
			// Clear the active portal since we're processing its response
			p.activePortal = ""
		}
	}

	// If no active portal, try to find a request of the preferred type
	if matchedRequest == nil && preferredType != "" {
		for key, req := range p.pendingRequests {
			if req.RequestType == preferredType {
				matchedKey = key
				matchedRequest = req
				break
			}
		}
	}

	// If still no match, find any request
	if matchedRequest == nil {
		for key, req := range p.pendingRequests {
			matchedKey = key
			matchedRequest = req
			break
		}
	}

	if matchedRequest != nil {
		output := p.buildOutputString(response, responseType, matchedRequest)

		pair := session.RequestResponsePair{
			Timestamp: matchedRequest.Timestamp,
			Input:     matchedRequest.Request,
			Output:    output,
		}

		if err := p.writePairToFile(pair); err != nil {
			log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to write request-response pair to file")
		}
		delete(p.pendingRequests, matchedKey)

		log.Debug().Str("sessionID", p.config.SessionID).Int("rowCount", matchedRequest.RowCount).Msg("Recorded query with data rows")
	}
}

func (p *PostgresProxy) cleanupPendingRequests() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Write all pending requests as incomplete pairs to file
	for key, req := range p.pendingRequests {
		incompletePair := session.RequestResponsePair{
			Timestamp: req.Timestamp,
			Input:     req.Request,
			Output:    "NO_RESPONSE", // No response received
		}

		if err := p.writePairToFile(incompletePair); err != nil {
			log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to write incomplete request-response pair to file")
		}
		delete(p.pendingRequests, key)
	}
}

func (p *PostgresProxy) writePairToFile(pair session.RequestResponsePair) error {
	entry := session.SessionLogEntry{
		Timestamp: pair.Timestamp,
		Input:     pair.Input,
		Output:    pair.Output,
	}

	return p.config.SessionLogger.LogEntry(entry)
}
