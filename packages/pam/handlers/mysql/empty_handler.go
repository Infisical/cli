package mysql

import (
	"github.com/go-mysql-org/go-mysql/mysql"
)

type EmptyHandler struct{}

func (e EmptyHandler) UseDB(dbName string) error {
	panic("Unexpected function call")
}

func (e EmptyHandler) HandleQuery(query string) (*mysql.Result, error) {
	panic("Unexpected function call")
}

func (e EmptyHandler) HandleFieldList(table string, fieldWildcard string) ([]*mysql.Field, error) {
	panic("Unexpected function call")
}

func (e EmptyHandler) HandleStmtPrepare(query string) (params int, columns int, context interface{}, err error) {
	panic("Unexpected function call")
}

func (e EmptyHandler) HandleStmtExecute(context interface{}, query string, args []interface{}) (*mysql.Result, error) {
	panic("Unexpected function call")
}

func (e EmptyHandler) HandleStmtClose(context interface{}) error {
	panic("Unexpected function call")
}

func (e EmptyHandler) HandleOtherCommand(cmd byte, data []byte) error {
	panic("Unexpected function call")
}
