package mysql

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/rs/zerolog/log"
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

	// Connection read and write timeouts to set on the connection
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// The buffer size to use in the packet connection
	BufferSize int
}

type MysqlProxy struct {
	config        MysqlProxyConfig
	relayHandler  *RelayHandler
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

	sessionID := p.config.SessionID

	// Ensure session logger cleanup
	defer func() {
		if err := p.sessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().
		Str("sessionID", sessionID).
		Msg("New MySQL connection for PAM session")

	// Initiate the connection from self to the actual server
	selfServerConn, err := p.connectToServer()
	if err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Msg("Failed to connect to MySQL server")
		return fmt.Errorf("failed to connect to MySQL server: %w", err)
	}
	defer selfServerConn.Close()

	// TODO: the server we are connecting to from self might have different cap flags
	//		 find a way to forward those
	clientSelfConn, err := server.NewServer(
		selfServerConn.GetServerVersion(),
		mysql.DEFAULT_COLLATION_ID,
		// TODO: not sure if this is the right way to go,
		// 		 but we probably only want to support a very few auth methods
		//		 since this server is only for forwarding purpose and we don't
		//		 care about auth now
		mysql.AUTH_NATIVE_PASSWORD,
		nil,
		nil,
	).NewCustomizedConn(
		clientConn,
		&AnyUserCredentialProvider{},
		// the UseDB method will be used during the auth process.
		UseDBHandler{conn: selfServerConn},
	)
	if err != nil {
		return fmt.Errorf("failed to accet MySQL client: %w", err)
	}

	p.relayHandler = NewRelayHandler(clientSelfConn, selfServerConn)

	p.relayHandler.HandleCommand()

	// TODO:
	return nil
}

func (p *MysqlProxy) connectToServer() (*client.Conn, error) {
	// TODO: psql implemented it with lower level api, but do we really need low level?
	// 		 let's try it with higher level and see if we need lower level
	conn, err := client.Connect(
		p.config.TargetAddr,
		p.config.InjectUsername,
		p.config.InjectPassword,
		p.config.InjectDatabase,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL server: %w", err)
	}
	// TODO: handle TLS conn
	return conn, nil
}
