package handlers

import (
	"context"
	"crypto/tls"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"net"
	"sync"
	"time"
)

// TODO: DRY with psql?
type MysqlProxyConfig struct {
	TargetAddr     string
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	EncryptionKey  string
	ExpiresAt      time.Time
}

type MysqlProxy struct {
	config        MysqlProxyConfig
	sessionLogger *session.SessionLogger
	mutex         sync.Mutex
	// TODO:
}

func NewMysqlProxy(config MysqlProxyConfig, sessionLogger *session.SessionLogger) *MysqlProxy {
	// TODO:
	return &MysqlProxy{
		config:        config,
		sessionLogger: sessionLogger,
	}
}

func (p *MysqlProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	// TODO:
	return nil
}
