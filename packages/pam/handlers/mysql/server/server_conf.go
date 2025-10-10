package server

import "github.com/go-mysql-org/go-mysql/mysql"

type Server struct {
	serverVersion     string // e.g. "8.0.12"
	protocolVersion   int    // minimal 10
	capability        uint32 // server capability flag
	collationId       uint8
	defaultAuthMethod string // default authentication method, 'mysql_native_password'
}

func NewServer(serverVersion string, collationId uint8, capFlag uint32) *Server {
	return &Server{
		serverVersion:     serverVersion,
		protocolVersion:   10,
		capability:        capFlag,
		collationId:       collationId,
		defaultAuthMethod: mysql.AUTH_NATIVE_PASSWORD,
	}
}
