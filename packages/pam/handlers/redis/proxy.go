package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

// RedisProxyConfig holds configuration for the Redis proxy
type RedisProxyConfig struct {
	TargetAddr     string
	InjectUsername string
	InjectPassword string
	InjectDatabase string // Redis database number (0-15)
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	SessionLogger  session.SessionLogger
}

// RedisProxy handles proxying Redis connections
type RedisProxy struct {
	config       RedisProxyConfig
	relayHandler *RelayHandler
}

// NewRedisProxy creates a new Redis proxy instance
func NewRedisProxy(config RedisProxyConfig) *RedisProxy {
	return &RedisProxy{config: config}
}

// HandleConnection handles a single client connection
func (p *RedisProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
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
		Msg("New Redis connection for PAM session")

	// Connect to the actual Redis server
	serverConn, err := p.connectToServer()
	if err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Msg("Failed to connect to Redis server")
		return fmt.Errorf("failed to connect to Redis server: %w", err)
	}
	defer serverConn.Close()

	// Authenticate with the server using injected credentials
	if err := p.authenticateToServer(serverConn); err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Msg("Failed to authenticate to Redis server")
		return fmt.Errorf("failed to authenticate to Redis server: %w", err)
	}

	// Select database if specified
	if p.config.InjectDatabase != "" {
		if err := p.selectDatabase(serverConn); err != nil {
			log.Error().Err(err).
				Str("sessionID", sessionID).
				Msg("Failed to select Redis database")
			return fmt.Errorf("failed to select Redis database: %w", err)
		}
	}

	// Create relay handler for logging
	p.relayHandler = NewRelayHandler(serverConn, p.config.SessionLogger)

	// Proxy messages bidirectionally
	errChan := make(chan error, 2)

	go p.proxyClientToServer(clientConn, serverConn, errChan)
	go p.proxyServerToClient(serverConn, clientConn, errChan)

	// Wait for either direction to error/close or context cancellation
	select {
	case err = <-errChan:
		if err != nil && err != io.EOF {
			log.Error().Err(err).
				Str("sessionID", sessionID).
				Msg("Connection error")
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

	return err
}

// connectToServer establishes a connection to the Redis server
func (p *RedisProxy) connectToServer() (net.Conn, error) {
	// TODO: Implement connection to Redis server
	// - Dial TCP connection to TargetAddr
	// - If EnableTLS is true, wrap connection with TLS using TLSConfig
	// - Return the connection

	conn, err := net.Dial("tcp", p.config.TargetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial Redis server: %w", err)
	}

	if p.config.EnableTLS {
		if p.config.TLSConfig == nil {
			conn.Close()
			return nil, fmt.Errorf("TLS configuration is required when TLS is enabled")
		}
		tlsConn := tls.Client(conn, p.config.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		log.Info().
			Str("sessionID", p.config.SessionID).
			Msg("Successfully established TLS connection to Redis server")
		return tlsConn, nil
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Msg("Connected to Redis server without TLS")
	return conn, nil
}

// authenticateToServer authenticates with the Redis server using injected credentials
func (p *RedisProxy) authenticateToServer(serverConn net.Conn) error {
	// TODO: Implement Redis authentication
	// - If InjectPassword is set, send AUTH command: "AUTH <password>\r\n"
	// - If InjectUsername is also set, send: "AUTH <username> <password>\r\n"
	// - Read and parse the response
	// - Check if response is OK or error
	// - Return error if authentication fails

	if p.config.InjectPassword == "" {
		// No authentication required
		return nil
	}

	// Build AUTH command
	var authCmd string
	if p.config.InjectUsername != "" {
		authCmd = fmt.Sprintf("AUTH %s %s\r\n", p.config.InjectUsername, p.config.InjectPassword)
	} else {
		authCmd = fmt.Sprintf("AUTH %s\r\n", p.config.InjectPassword)
	}

	// Send AUTH command
	if _, err := serverConn.Write([]byte(authCmd)); err != nil {
		return fmt.Errorf("failed to send AUTH command: %w", err)
	}

	// Read response
	// TODO: Parse RESP protocol response
	// For now, just read a simple response
	response := make([]byte, 5) // "+OK\r\n" is 5 bytes
	if _, err := serverConn.Read(response); err != nil {
		return fmt.Errorf("failed to read AUTH response: %w", err)
	}

	// Check if response is OK
	if string(response) != "+OK\r\n" {
		return fmt.Errorf("authentication failed: %s", string(response))
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Msg("Successfully authenticated to Redis server")
	return nil
}

// selectDatabase selects the Redis database
func (p *RedisProxy) selectDatabase(serverConn net.Conn) error {
	// TODO: Implement database selection
	// - Send SELECT command: "SELECT <database>\r\n"
	// - Read and parse the response
	// - Check if response is OK or error
	// - Return error if selection fails

	if p.config.InjectDatabase == "" {
		return nil
	}

	selectCmd := fmt.Sprintf("SELECT %s\r\n", p.config.InjectDatabase)
	if _, err := serverConn.Write([]byte(selectCmd)); err != nil {
		return fmt.Errorf("failed to send SELECT command: %w", err)
	}

	// Read response
	response := make([]byte, 5) // "+OK\r\n" is 5 bytes
	if _, err := serverConn.Read(response); err != nil {
		return fmt.Errorf("failed to read SELECT response: %w", err)
	}

	// Check if response is OK
	if string(response) != "+OK\r\n" {
		return fmt.Errorf("database selection failed: %s", string(response))
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Str("database", p.config.InjectDatabase).
		Msg("Successfully selected Redis database")
	return nil
}

// proxyClientToServer proxies data from client to server
func (p *RedisProxy) proxyClientToServer(clientConn, serverConn net.Conn, errChan chan error) {
	// TODO: Implement client-to-server proxying with command logging
	// - Read RESP commands from client
	// - Parse commands for logging
	// - Forward commands to server
	// - Log commands using relayHandler

	buffer := make([]byte, 4096)
	for {
		n, err := clientConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				errChan <- err
			} else {
				errChan <- nil
			}
			return
		}

		if n == 0 {
			continue
		}

		// Log the command
		// TODO: Parse RESP protocol to extract command name and arguments
		command := string(buffer[:n])
		p.relayHandler.LogCommand(command)

		// Forward to server
		if _, err := serverConn.Write(buffer[:n]); err != nil {
			errChan <- err
			return
		}
	}
}

// proxyServerToClient proxies data from server to client
func (p *RedisProxy) proxyServerToClient(serverConn, clientConn net.Conn, errChan chan error) {
	// TODO: Implement server-to-client proxying with response logging
	// - Read RESP responses from server
	// - Parse responses for logging
	// - Forward responses to client
	// - Log responses using relayHandler

	buffer := make([]byte, 4096)
	for {
		n, err := serverConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				errChan <- err
			} else {
				errChan <- nil
			}
			return
		}

		if n == 0 {
			continue
		}

		// Log the response
		// TODO: Parse RESP protocol to format response nicely
		response := string(buffer[:n])
		p.relayHandler.LogResponse(response)

		// Forward to client
		if _, err := clientConn.Write(buffer[:n]); err != nil {
			errChan <- err
			return
		}
	}
}
