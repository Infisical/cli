package redis

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

// RelayHandler handles relaying commands and responses between client and server
type RelayHandler struct {
	serverConn       net.Conn
	sessionLogger    session.SessionLogger
	closed           atomic.Bool
	currentCommand   string
	commandStartTime time.Time
}

// NewRelayHandler creates a new relay handler
func NewRelayHandler(serverConn net.Conn, sessionLogger session.SessionLogger) *RelayHandler {
	return &RelayHandler{
		serverConn:    serverConn,
		sessionLogger: sessionLogger,
		closed:        atomic.Bool{},
	}
}

// Closed returns whether the handler is closed
func (r *RelayHandler) Closed() bool {
	return r.closed.Load()
}

// LogCommand logs a command received from the client
func (r *RelayHandler) LogCommand(command string) {
	// TODO: Implement command logging
	// - Parse RESP protocol to extract command name and arguments
	// - Format command for logging (e.g., "GET key", "SET key value")
	// - Store command and timestamp for later pairing with response

	r.currentCommand = command
	r.commandStartTime = time.Now()

	log.Debug().
		Str("command", command).
		Msg("Received Redis command from client")
}

// LogResponse logs a response received from the server
func (r *RelayHandler) LogResponse(response string) {
	// TODO: Implement response logging
	// - Parse RESP protocol to format response nicely
	// - Pair response with the last logged command
	// - Write request-response pair to session logger

	if r.currentCommand == "" {
		// No command to pair with, just log the response
		log.Debug().
			Str("response", response).
			Msg("Received Redis response from server (no command to pair)")
		return
	}

	// Format the response for logging
	formattedResponse := r.formatResponse(response)

	// Create log entry
	entry := session.SessionLogEntry{
		Timestamp: r.commandStartTime,
		Input:     r.formatCommand(r.currentCommand),
		Output:    formattedResponse,
	}

	if err := r.sessionLogger.LogEntry(entry); err != nil {
		log.Error().Err(err).Msg("Failed to write log entry to file")
	}

	// Clear current command
	r.currentCommand = ""
}

// formatCommand formats a raw RESP command for logging
func (r *RelayHandler) formatCommand(command string) string {
	// TODO: Implement command formatting
	// - Parse RESP protocol (arrays start with *)
	// - Extract command name and arguments
	// - Format as "COMMAND arg1 arg2 ..."
	// - Example: "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n" -> "GET key"

	// For now, return as-is (will be implemented later)
	return command
}

// formatResponse formats a raw RESP response for logging
func (r *RelayHandler) formatResponse(response string) string {
	// TODO: Implement response formatting
	// - Parse RESP protocol
	// - Format different response types:
	//   - Simple strings: "+OK\r\n" -> "OK"
	//   - Errors: "-ERR ...\r\n" -> "ERROR: ..."
	//   - Integers: ":123\r\n" -> "123"
	//   - Bulk strings: "$5\r\nhello\r\n" -> "hello"
	//   - Arrays: "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n" -> "[foo, bar]"
	// - Handle null responses: "$-1\r\n" -> "NULL"

	// For now, return as-is (will be implemented later)
	return response
}

// Close closes the relay handler
func (r *RelayHandler) Close() error {
	r.closed.Store(true)
	if r.serverConn != nil {
		return r.serverConn.Close()
	}
	return nil
}
