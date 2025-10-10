package server

import (
	"bytes"
	"fmt"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/errors"
)

var (
	ErrAccessDenied           = errors.New("access denied")
	ErrAccessDeniedNoPassword = fmt.Errorf("%w without password", ErrAccessDenied)
)

func (c *Conn) compareAuthData(authPluginName string, clientAuthData []byte) error {
	switch authPluginName {
	case mysql.AUTH_NATIVE_PASSWORD:
		return c.compareNativePasswordAuthData(clientAuthData, c.password)
	default:
		return errors.Errorf("unknown authentication plugin name '%s'", authPluginName)
	}
}

func errAccessDenied(password string) error {
	if password == "" {
		return ErrAccessDeniedNoPassword
	}

	return ErrAccessDenied
}

func (c *Conn) compareNativePasswordAuthData(clientAuthData []byte, password string) error {
	if bytes.Equal(mysql.CalcPassword(c.salt, []byte(password)), clientAuthData) {
		return nil
	}
	return errAccessDenied(password)
}
