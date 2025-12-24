package redis

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
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
			// Handle auth command, we just reply OK instead of forwarding it to the server
			case "auth":
				err := h.clientToSelfConn.WriteValue(&resp3.Value{Type: resp3.TypeSimpleString, Str: "OK"}, true)
				if err != nil {
					return err
				}
				break
			// TODO: handle monitor / subscribe and other special commands
			// Forward all other commands
			default:
				err := h.selfToServerConn.WriteValue(value, true)
				if err != nil {
					h.writeLogEntry(value, nil)
					return err
				}

				respVal, _, err := h.selfToServerConn.Reader().ReadValue()
				h.writeLogEntry(value, respVal)
				err = h.clientToSelfConn.WriteValue(respVal, true)
				if err != nil {
					return err
				}
			}
		default:
			if err = h.clientToSelfConn.WriteValue(&resp3.Value{Type: resp3.TypeSimpleError, Err: fmt.Sprintf("Unexpected value type %v", value.Type)}, true); err != nil {
				return err
			}
			return fmt.Errorf("unexpected value type %v", value.Type)
		}
	}
}

func (r *RelayHandler) writeLogEntry(cmd *resp3.Value, resp *resp3.Value) {
	input, err := valueToJson(cmd)
	if err != nil {
		log.Error().Err(err).Msg("failed to convert cmd value to json")
		return
	}
	output := ""
	if resp != nil {
		output, err = valueToJson(resp)
		if err != nil {
			log.Error().Err(err).Msg("failed to convert resp value to json")
			return
		}
	}

	err = r.sessionLogger.LogEntry(session.SessionLogEntry{
		Timestamp: time.Now(),
		Input:     input,
		Output:    output,
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to write log entry to file")
	}
}

func valueToJson(value *resp3.Value) (string, error) {
	v := value.SmartResult()
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
