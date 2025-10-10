package mysql

import (
	"fmt"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/rs/zerolog/log"
	"time"
)

type RelayHandler struct {
	clientSelfConn *server.Conn
	selfServerConn *client.Conn
	sessionLogger  session.SessionLogger
}

func (r RelayHandler) UseDB(dbName string) error {
	return r.selfServerConn.UseDB(dbName)
}

func (r RelayHandler) HandleQuery(query string) (*mysql.Result, error) {
	result, err := r.selfServerConn.Execute(query)
	if err != nil {
		r.writeLogEntry(session.SessionLogEntry{
			Timestamp: time.Now(),
			Input:     query,
			// TODO: put error here?
			Output: "NO_RESPONSE",
		})
		return nil, err
	}
	return result, nil
}

func (r RelayHandler) HandleFieldList(table string, fieldWildcard string) ([]*mysql.Field, error) {
	// Note that COM_FIELD_LIST has been deprecated since MySQL 5.7.11. Now need to support it right now
	// ref: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_field_list.html
	return nil, fmt.Errorf("not supported now")
}

func (r RelayHandler) HandleStmtPrepare(query string) (params int, columns int, context interface{}, err error) {
	stmt, err := r.selfServerConn.Prepare(query)
	if err != nil {
		return 0, 0, nil, err
	}
	return stmt.ParamNum(), stmt.ColumnNum(), stmt, nil
}

func (r RelayHandler) HandleStmtExecute(context interface{}, query string, args []interface{}) (*mysql.Result, error) {
	stmt := context.(*client.Stmt)
	result, err := stmt.Execute(args...)
	if err != nil {
		r.writeLogEntry(session.SessionLogEntry{
			Timestamp: time.Now(),
			Input:     query,
			Output:    "NO_RESPONSE", // No response received
		})
		return nil, err
	}
	r.writeLogEntry(session.SessionLogEntry{
		Timestamp: time.Now(),
		Input:     query,
		// TODO: parse the resp and log it
		Output: "FIXME",
	})
	return result, err
}

func (r RelayHandler) HandleStmtClose(context interface{}) error {
	stmt := context.(*client.Stmt)
	return stmt.Close()
}

func (r RelayHandler) HandleOtherCommand(cmd byte, data []byte) error {
	log.Info().Str("command", string(cmd)).Msg("Received unsupported command")
	return fmt.Errorf("not supported now")
}

func NewRelayHandler(clientSelfConn *server.Conn, selfServerConn *client.Conn, sessionLogger session.SessionLogger) *RelayHandler {
	return &RelayHandler{clientSelfConn, selfServerConn, sessionLogger}
}

func (r *RelayHandler) SetClientSelfConn(clientSelfConn *server.Conn) {
	r.clientSelfConn = clientSelfConn
}

func (r RelayHandler) writeLogEntry(entry session.SessionLogEntry) (*mysql.Result, error) {
	err := r.sessionLogger.LogEntry(entry)
	if err != nil {
		log.Error().Err(err).Msg("failed to write log entry to file")
		return nil, err
	}
	return nil, nil
}
