package mysql

import (
	"fmt"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/rs/zerolog/log"
)

type RelayHandler struct {
	clientSelfConn *server.Conn
	selfServerConn *client.Conn
}

// Originally defined for internal use in go-mysql. We took it and add our own special
// response like forward resp from the server
type (
	// Do not send anything to the client
	noResponse struct{}
	// Forward the request to the server only
	forwardRequestOnly struct{}
	// Forward the request to server and the response to the client
	forwardRequestResponse struct{}
)

func NewRelayHandler(clientSelfConn *server.Conn, selfServerConn *client.Conn) *RelayHandler {
	return &RelayHandler{clientSelfConn, selfServerConn}
}

// mostly identical to the go-mysql's implementation for their Handler
// ref: https://github.com/go-mysql-org/go-mysql/blob/558ed11751bc82177944e5d411f46b76f9c64102/server/command.go#L46-L71
func (h *RelayHandler) HandleCommand() error {
	c := h.clientSelfConn
	if c.Conn == nil {
		return fmt.Errorf("connection closed")
	}

	data, err := c.ReadPacket()
	if err != nil {
		c.Close()
		c.Conn = nil
		return err
	}

	resp := h.dispatch(data)
	switch v := resp.(type) {
	case noResponse:
		// Do nothing
		{
		}
	case forwardRequestResponse:
		err := h.forwardRequestResponse(data)
		if err != nil {
			return err
		}
	default:
		c.WriteValue(v)
	}

	if c.Conn != nil {
		c.ResetSequence()
	}

	if err != nil {
		c.Close()
		c.Conn = nil
	}
	return err
}

func (h *RelayHandler) forwardRequestResponse(data []byte) error {
	c := h.clientSelfConn
	s := h.selfServerConn

	// Forward the packet to the server
	err := s.WritePacket(data)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to forward client-to-relay request to the server")
		return err
	}
	// Read the resp from the server and forward them to the client until EOF
	for true {
		resp, err := s.ReadPacket()
		if err != nil {
			log.Error().Err(err).Msgf("Failed to read server-to-relay response from the server")
			return err
		}
		cmd := data[0]
		eof := cmd == mysql.EOF_HEADER

		// Forward the server's response back to the client
		err = c.WritePacket(resp)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to write server-to-relay response to the client")
			return err
		}
		if eof {
			break
		}
	}
	return nil
}

func (h *RelayHandler) dispatch(data []byte) interface{} {
	c := h.clientSelfConn
	cmd := data[0]
	data = data[1:]

	switch cmd {
	case mysql.COM_QUIT:
		c.Close()
		c.Conn = nil
		// TODO: handle server side shutdown as well
		return noResponse{}
	case mysql.COM_QUERY:
		// TODO: track the query
		return forwardRequestResponse{}
	case mysql.COM_PING:
	case mysql.COM_INIT_DB:
	case mysql.COM_FIELD_LIST:
		return forwardRequestResponse{}
	case mysql.COM_STMT_PREPARE:
		// TODO: track the query
		return forwardRequestResponse{}
	case mysql.COM_STMT_EXECUTE:
		// TODO: track the query
		return forwardRequestResponse{}
	case mysql.COM_STMT_CLOSE:
		// TODO: track the query
		return forwardRequestResponse{}
	case mysql.COM_STMT_SEND_LONG_DATA:
		// TODO: track the query
		return forwardRequestOnly{}
	case mysql.COM_STMT_RESET:
		// TODO: track the query
		return forwardRequestResponse{}
	case mysql.COM_SET_OPTION:
		// TODO: track the query
		return forwardRequestResponse{}
	case mysql.COM_REGISTER_SLAVE:
		return forwardRequestResponse{}
	case mysql.COM_BINLOG_DUMP:
		return forwardRequestResponse{}
	case mysql.COM_BINLOG_DUMP_GTID:
		return forwardRequestResponse{}
	default:
		return forwardRequestResponse{}
	}
	return nil
}
