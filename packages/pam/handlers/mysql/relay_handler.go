package mysql

import (
	"encoding/json"
	"fmt"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"sync/atomic"
	"time"
)

type RelayHandler struct {
	selfServerConn *client.Conn
	sessionLogger  session.SessionLogger
	closed         atomic.Bool
}

func NewRelayHandler(selfServerConn *client.Conn, sessionLogger session.SessionLogger) *RelayHandler {
	return &RelayHandler{selfServerConn, sessionLogger, atomic.Bool{}}
}

func (r *RelayHandler) Closed() bool {
	return r.closed.Load()
}

func (r *RelayHandler) UseDB(dbName string) error {
	err := r.selfServerConn.UseDB(dbName)
	r.checkConnLostError(err)
	return err
}

func (r *RelayHandler) HandleQuery(query string) (*mysql.Result, error) {
	result, err := r.selfServerConn.Execute(query)
	r.checkConnLostError(err)
	if err != nil {
		r.writeLogEntry(session.SessionLogEntry{
			Timestamp: time.Now(),
			Input:     query,
			// TODO: put error here?
			Output: "NO_RESPONSE",
		})
		return nil, err
	}
	r.writeLogEntry(session.SessionLogEntry{
		Timestamp: time.Now(),
		Input:     query,
		Output:    formatResult(result),
	})
	return result, nil
}

func (r *RelayHandler) HandleFieldList(table string, fieldWildcard string) ([]*mysql.Field, error) {
	// Note that COM_FIELD_LIST has been deprecated since MySQL 5.7.11. Now need to support it right now
	// ref: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_field_list.html
	return nil, fmt.Errorf("not supported now")
}

func (r *RelayHandler) HandleStmtPrepare(query string) (params int, columns int, context interface{}, err error) {
	stmt, err := r.selfServerConn.Prepare(query)
	r.checkConnLostError(err)
	if err != nil {
		return 0, 0, nil, err
	}
	return stmt.ParamNum(), stmt.ColumnNum(), stmt, nil
}

func (r *RelayHandler) HandleStmtExecute(context interface{}, query string, args []interface{}) (*mysql.Result, error) {
	stmt := context.(*client.Stmt)
	result, err := stmt.Execute(args...)
	r.checkConnLostError(err)
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
		Output:    formatResult(result),
	})
	return result, err
}

func (r *RelayHandler) HandleStmtClose(context interface{}) error {
	stmt := context.(*client.Stmt)
	return stmt.Close()
}

func (r *RelayHandler) HandleOtherCommand(cmd byte, data []byte) error {
	log.Info().Str("command", string(cmd)).Msg("Received unsupported command")
	return fmt.Errorf("not supported now")
}

func (r *RelayHandler) checkConnLostError(err error) {
	if errors.Cause(err) == mysql.ErrBadConn {
		r.closed.Store(true)
		r.selfServerConn.Close()
		r.selfServerConn = nil
	}
}

func (r *RelayHandler) writeLogEntry(entry session.SessionLogEntry) (*mysql.Result, error) {
	err := r.sessionLogger.LogEntry(entry)
	if err != nil {
		log.Error().Err(err).Msg("failed to write log entry to file")
		return nil, err
	}
	return nil, nil
}

func formatResult(result *mysql.Result) string {
	dataRows := make([]map[string]interface{}, 0, len(result.Values))
	for i := 0; i < len(result.Values); i += 1 {
		row := make(map[string]interface{}, len(result.Fields))
		for j := 0; j < len(result.Values[i]); j += 1 {
			field := result.Fields[j]
			row[string(field.Name)] = result.Values[i][j].String()
		}
		dataRows = append(dataRows, row)
	}

	outputData := map[string]interface{}{
		"total_rows": len(result.Values),
		"data_rows":  dataRows,
	}
	if jsonBytes, err := json.Marshal(outputData); err == nil {
		return string(jsonBytes)
	} else {
		return fmt.Sprintf("query (returned %d rows, JSON error: %v)", len(result.Values), err)
	}
}
