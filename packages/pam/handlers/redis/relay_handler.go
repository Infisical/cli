package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

type LogType string

const (
	LogTypeCmd  LogType = "cmd"
	LogTypePush LogType = "push"
)

type RedisLogEntry struct {
	LogType LogType     `json:"type"`
	Cmd     interface{} `json:"cmd,omitempty"`
}

type serverReply struct {
	value *resp3.Value
	err   error
}

// NewRelayHandler creates a new relay handler
func NewRelayHandler(clientToSelfConn *RedisConn, selfToServerConn *RedisConn, sessionLogger session.SessionLogger) *RelayHandler {
	return &RelayHandler{
		clientToSelfConn: clientToSelfConn,
		selfToServerConn: selfToServerConn,
		sessionLogger:    sessionLogger,
	}
}

func (h *RelayHandler) Handle(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	serverReplyCh := make(chan serverReply, 1)
	go func(ch chan<- serverReply) {
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			if err := h.selfToServerConn.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				log.Error().Err(err).Msg("failed to set read deadline")
				ch <- serverReply{nil, err}
				return
			}
			v, _, err := h.selfToServerConn.Reader().ReadValue()
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				log.Error().Err(err).Msg("Error reading from server")
				ch <- serverReply{nil, err}
				return
			} else if (v.Type == resp3.TypeArray && len(v.Elems) > 0 && strings.ToLower(v.Elems[0].Str) == "message") ||
				(v.Type == resp3.TypePush) {
				// pubsub in resp2/resp3 mode will send a push as the confirmation instead of return anything,
				// we need to treat that as a cmd reply otherwise the main loop will wait forever for the
				// server reply to forward
				if !isPubSubConfirmation(v) {
					err = h.clientToSelfConn.WriteValue(v, true)
					if err != nil {
						log.Error().Err(err).Msg("Error forwarding push messages to server")
						ch <- serverReply{nil, err}
						return
					}
					h.writeLogEntry(LogTypePush, nil, v)
					continue
				}
			}
			select {
			case ch <- serverReply{v, nil}:
			case <-ctx.Done():
				return
			}
		}
	}(serverReplyCh)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := h.clientToSelfConn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			return err
		}
		value, _, err := h.clientToSelfConn.Reader().ReadValue()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
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
			// TODO: with reset cmd, should we send out AUTH again automatically to the server?
			// Forward all other commands
			default:
				err := h.selfToServerConn.WriteValue(value, true)
				if err != nil {
					h.writeLogEntry(LogTypeCmd, value, nil)
					return err
				}

				reply := <-serverReplyCh
				if reply.err != nil {
					return reply.err
				}
				h.writeLogEntry(LogTypeCmd, value, reply.value)
				err = h.clientToSelfConn.WriteValue(reply.value, true)
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

func (r *RelayHandler) writeLogEntry(logType LogType, cmd *resp3.Value, resp *resp3.Value) {
	entry := RedisLogEntry{
		LogType: logType,
	}
	if logType == LogTypeCmd {
		entry.Cmd = cmd.SmartResult()
	}
	input, err := valueToJson(entry)
	if err != nil {
		log.Error().Err(err).Msg("failed to convert cmd value to json")
		return
	}
	output := ""
	if resp != nil {
		output, err = valueToJson(resp.SmartResult())
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

func valueToJson(value interface{}) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func isPubSubConfirmation(value *resp3.Value) bool {
	if len(value.Elems) < 1 {
		return false
	}
	switch strings.ToLower(value.Elems[0].Str) {
	case "subscribe", "psubscribe", "ssubscribe", "unsubscribe", "punsubscribe", "sunsubscribe":
		return true
	}
	return false
}
