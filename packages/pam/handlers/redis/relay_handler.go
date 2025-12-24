package redis

import (
	"context"
	"net"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/redis/go-redis/v9"
	"github.com/tidwall/redcon"
)

// RelayHandler handles relaying commands and responses between client and server
type RelayHandler struct {
	clientToSelfConn   net.Conn
	clientToSelfReader *redcon.Reader
	clientToSelfWriter *redcon.Writer
	selfToServerClient *redis.Client
	sessionLogger      session.SessionLogger
}

// NewRelayHandler creates a new relay handler
func NewRelayHandler(clientToSelfConn net.Conn, selfToServerClient *redis.Client, sessionLogger session.SessionLogger) *RelayHandler {
	return &RelayHandler{
		clientToSelfConn:   clientToSelfConn,
		clientToSelfReader: redcon.NewReader(clientToSelfConn),
		clientToSelfWriter: redcon.NewWriter(clientToSelfConn),
		selfToServerClient: selfToServerClient,
		sessionLogger:      sessionLogger,
	}
}

func (h *RelayHandler) Handle() error {
	for {
		cmd, err := h.clientToSelfReader.ReadCommand()
		if err != nil {
			return err
		}
		switch strings.ToLower(string(cmd.Args[0])) {
		case "auth":
			// Ignore what ever auth cmd they send us, just reply ok
			h.clientToSelfWriter.WriteString("OK")
			err := h.clientToSelfWriter.Flush()
			if err != nil {
				return err
			}
			break
		default:
			// TODO: add logs here
			r, _ := h.selfToServerClient.Do(context.Background(), cmd.Args).Result()
			h.clientToSelfWriter.WriteAny(r)
			err := h.clientToSelfWriter.Flush()
			if err != nil {
				return err
			}
		}
	}
}
