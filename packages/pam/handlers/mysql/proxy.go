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
	SessionLogger  session.SessionLogger

	// Connection read and write timeouts to set on the connection
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// The buffer size to use in the packet connection
	BufferSize int
}

type MysqlProxy struct {
	config       MysqlProxyConfig
	relayHandler *RelayHandler
	mutex        sync.Mutex
	// TODO:
}

func NewMysqlProxy(config MysqlProxyConfig) *MysqlProxy {
	return &MysqlProxy{config: config}
}

func (p *MysqlProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	sessionID := p.config.SessionID

	// Ensure session logger cleanup
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
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

	actualServer := server.NewServer(
		// Let's use a conservative version to let the client not to throw
		// many too fancy stuff at us to get the V1 out of door fast
		"8.0.11",
		mysql.DEFAULT_COLLATION_ID,
		mysql.AUTH_NATIVE_PASSWORD,
		nil,
		nil,
	)
	p.relayHandler = NewRelayHandler(nil, selfServerConn, p.config.SessionLogger)
	clientSelfConn, err := actualServer.NewCustomizedConn(
		clientConn,
		&AnyUserCredentialProvider{},
		p.relayHandler,
	)
	if err != nil {
		return fmt.Errorf("failed to accet MySQL client: %w", err)
	}
	defer func() {
		if !clientSelfConn.Closed() {
			clientSelfConn.Close()
		}
	}()
	p.relayHandler.SetClientSelfConn(clientSelfConn)

	// TODO: check if selfServerConn closed or no
	// TODO: check if clientSelfConn closed or not, somehow the read in HandleCommand doesn't raise error even
	//	     when the connection is closed.
	for !clientSelfConn.Closed() {
		err = clientSelfConn.HandleCommand()
		if err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to handle command")
			return err
		}
	}

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
