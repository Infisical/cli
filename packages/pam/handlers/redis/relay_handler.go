package redis

import (
	"fmt"
	"net"
	"strings"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/smallnest/resp3"
)

// RelayHandler handles relaying commands and responses between client and server
type RelayHandler struct {
	clientToSelfConn   net.Conn
	clientToSelfReader *resp3.Reader
	clientToSelfWriter *resp3.Writer
	selfToServerConn   net.Conn
	selfToServerWriter *resp3.Writer
	selfToServerReader *resp3.Reader
	sessionLogger      session.SessionLogger
}

// NewRelayHandler creates a new relay handler
func NewRelayHandler(clientToSelfConn net.Conn, selfToServerConn net.Conn, sessionLogger session.SessionLogger) *RelayHandler {
	return &RelayHandler{
		clientToSelfConn:   clientToSelfConn,
		clientToSelfReader: resp3.NewReader(clientToSelfConn),
		clientToSelfWriter: resp3.NewWriter(clientToSelfConn),
		selfToServerConn:   selfToServerConn,
		selfToServerWriter: resp3.NewWriter(selfToServerConn),
		selfToServerReader: resp3.NewReader(selfToServerConn),
		sessionLogger:      sessionLogger,
	}
}

func (h *RelayHandler) Handle() error {
	for {
		value, _, err := h.clientToSelfReader.ReadValue()
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
				_, err := h.clientToSelfWriter.WriteString(r.ToRESP3String())
				if err != nil {
					return err
				}
				err = h.clientToSelfWriter.Flush()
				if err != nil {
					return err
				}
				break
			default:
				_, err := h.selfToServerWriter.WriteString(value.ToRESP3String())
				if err != nil {
					return err
				}
				err = h.selfToServerWriter.Flush()
				if err != nil {
					return err
				}

				respVal, _, err := h.selfToServerReader.ReadValue()
				_, err = h.clientToSelfWriter.WriteString(respVal.ToRESP3String())
				if err != nil {
					return err
				}

				err = h.clientToSelfWriter.Flush()
				if err != nil {
					return err
				}
			}
		default:
			// TODO: return error
		}
	}
}
