package redis

import (
	"net"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
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

func (h *RelayHandler) Handle() error {
	for {
		cmd, err := h.reader.ReadCommand()
		if err != nil {
			return err
		}
		switch strings.ToLower(string(cmd.Args[0])) {
		case "ping":
			log.Info().Msg("PING")
		}
	}
}
