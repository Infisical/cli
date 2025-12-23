package redis

import (
	"net"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/tidwall/redcon"
)

// RelayHandler handles relaying commands and responses between client and server
type RelayHandler struct {
	serverConn    net.Conn
	sessionLogger session.SessionLogger
	reader        *redcon.Reader
}

// NewRelayHandler creates a new relay handler
func NewRelayHandler(serverConn net.Conn, sessionLogger session.SessionLogger) *RelayHandler {
	return &RelayHandler{
		serverConn:    serverConn,
		sessionLogger: sessionLogger,
		reader:        redcon.NewReader(serverConn),
	}
}
