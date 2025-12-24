package redis

import (
	"fmt"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/smallnest/resp3"
)

// RelayHandler handles relaying commands and responses between client and server
type RelayHandler struct {
	clientToSelfConn *RedisConn
	selfToServerConn *RedisConn
	sessionLogger    session.SessionLogger
}

// NewRelayHandler creates a new relay handler
func NewRelayHandler(clientToSelfConn *RedisConn, selfToServerConn *RedisConn, sessionLogger session.SessionLogger) *RelayHandler {
	return &RelayHandler{
		clientToSelfConn: clientToSelfConn,
		selfToServerConn: selfToServerConn,
		sessionLogger:    sessionLogger,
	}
}

func (h *RelayHandler) Handle() error {

	for {
		value, _, err := h.clientToSelfConn.Reader().ReadValue()
		if err != nil {
			return err
		}
		switch value.Type {
		case resp3.TypeArray:
			cmd := value.Elems[0]
			if cmd.Type != resp3.TypeBlobString {
				return fmt.Errorf("expected SimpleString, got %s", cmd.Type)
			}
			cmdStr := strings.ToLower(value.Elems[0].Str)
			switch cmdStr {
			case "auth":
				r := resp3.Value{Type: resp3.TypeSimpleString, Str: "OK"}
				_, err := h.clientToSelfConn.Writer().WriteString(r.ToRESP3String())
				if err != nil {
					return err
				}
				err = h.clientToSelfConn.Writer().Flush()
				if err != nil {
					return err
				}
				break
			default:
				_, err := h.selfToServerConn.Writer().WriteString(value.ToRESP3String())
				if err != nil {
					return err
				}
				err = h.selfToServerConn.Writer().Flush()
				if err != nil {
					return err
				}

				respVal, _, err := h.selfToServerConn.Reader().ReadValue()
				_, err = h.clientToSelfConn.Writer().WriteString(respVal.ToRESP3String())
				if err != nil {
					return err
				}

				err = h.clientToSelfConn.Writer().Flush()
				if err != nil {
					return err
				}
			}
		default:
			// TODO: return error
		}
	}
}
