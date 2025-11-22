package mysql

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	sqi "github.com/Infisical/sql-query-identifier"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type RelayHandler struct {
	selfServerConn *client.Conn
	sessionLogger  session.SessionLogger
	closed         atomic.Bool
	config         MysqlProxyConfig
}

func NewRelayHandler(selfServerConn *client.Conn, sessionLogger session.SessionLogger, config MysqlProxyConfig) *RelayHandler {
	return &RelayHandler{selfServerConn, sessionLogger, atomic.Bool{}, config}
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
	if r.config.ReadOnlyMode {
		isReadOnly, err := r.handleReadOnlyCheck(query)
		if err != nil {
			return nil, err
		}
		if !isReadOnly {
			return nil, mysql.NewError(mysql.ER_OPTION_PREVENTS_STATEMENT, "Operation not allowed by policy in read-only mode.")
		}
	}
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
	if r.config.ReadOnlyMode {
		isReadOnly, err := r.handleReadOnlyCheck(query)
		if err != nil {
			return 0, 0, nil, err
		}
		if !isReadOnly {
			return 0, 0, nil, mysql.NewError(mysql.ER_OPTION_PREVENTS_STATEMENT, "Operation not allowed by policy in read-only mode.")
		}
	}
	stmt, err := r.selfServerConn.Prepare(query)
	r.checkConnLostError(err)
	if err != nil {
		return 0, 0, nil, err
	}
	return stmt.ParamNum(), stmt.ColumnNum(), stmt, nil
}

func (r *RelayHandler) HandleStmtExecute(context interface{}, query string, args []interface{}) (*mysql.Result, error) {
	if r.config.ReadOnlyMode {
		isReadOnly, err := r.handleReadOnlyCheck(query)
		if err != nil {
			return nil, err
		}
		if !isReadOnly {
			return nil, mysql.NewError(mysql.ER_OPTION_PREVENTS_STATEMENT, "Operation not allowed by policy in read-only mode.")
		}
	}
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

func (r *RelayHandler) handleReadOnlyCheck(query string) (bool, error) {
	if query == "" {
		return true, nil
	}

	dialect := sqi.DialectMySQL
	strict := false
	options := sqi.IdentifyOptions{
		Dialect: &dialect,
		Strict:  &strict,
	}

	identifiedQueries, err := sqi.Identify(query, options)
	if err != nil {
		log.Error().
			Str("sessionID", r.config.SessionID).
			Str("query", query).
			Err(err).
			Msg("Failed to identify query; blocking in read-only mode.")
		return false, err
	}

	// verify that every statement in the query is read-only
	for _, identifiedQuery := range identifiedQueries {
		if identifiedQuery.ExecutionType != sqi.ExecutionListing && identifiedQuery.ExecutionType != sqi.ExecutionInformation {
			log.Warn().
				Str("sessionID", r.config.SessionID).
				Str("query", query).
				Str("executionType", string(identifiedQuery.ExecutionType)).
				Msg("Write query blocked in read-only mode.")
			return false, nil
		}
	}

	return true, nil
}

func formatResult(result *mysql.Result) string {
	if result.Resultset != nil {
		return fmt.Sprintf("SUCCESS (%d rows affected)", len(result.Resultset.Values))
	}
	return fmt.Sprintf("SUCCESS (%d rows affected)", result.AffectedRows)
}
