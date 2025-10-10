// The following code is modified from go-mysql. Original LICENSE MIT or BSD
// Since it has capability value fixed and there's no easy way to change it, therefore we implement our own
// based on their code
// ref: https://github.com/go-mysql-org/go-mysql/blob/558ed11751bc82177944e5d411f46b76f9c64102/server/server_conf.go
package server

type Server struct {
	serverVersion   string // e.g. "8.0.12"
	protocolVersion int    // minimal 10
	capability      uint32 // server capability flag
	collationId     uint8
}

func NewServer(serverVersion string, collationId uint8, capFlag uint32) *Server {
	return &Server{
		serverVersion:   serverVersion,
		protocolVersion: 10,
		capability:      capFlag,
		collationId:     collationId,
	}
}
