package mysql

import (
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
)

type UseDBHandler struct {
	conn *client.Conn
}

func (h UseDBHandler) UseDB(dbName string) error {
	return h.conn.UseDB(dbName)
}

func (h UseDBHandler) HandleQuery(query string) (*mysql.Result, error) {
	panic("Unexpected function call")
}

func (h UseDBHandler) HandleFieldList(table string, fieldWildcard string) ([]*mysql.Field, error) {
	panic("Unexpected function call")
}

func (h UseDBHandler) HandleStmtPrepare(query string) (params int, columns int, context interface{}, err error) {
	panic("Unexpected function call")
}

func (h UseDBHandler) HandleStmtExecute(context interface{}, query string, args []interface{}) (*mysql.Result, error) {
	panic("Unexpected function call")
}

func (h UseDBHandler) HandleStmtClose(context interface{}) error {
	panic("Unexpected function call")
}

func (h UseDBHandler) HandleOtherCommand(cmd byte, data []byte) error {
	panic("Unexpected function call")
}
