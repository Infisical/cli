package mysql

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/mysql/server"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
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

	// TODO: this is a bit silly that we need to iterate over all the possible bits.
	//	     we should create PR in the upstream to expose the Capability uint32 value
	//	     directly
	capFlags := getCapabilities(func(flag uint32) bool {
		return selfServerConn.HasCapability(flag)
	})
	// TODO: the server we are connecting to from self might have different cap flags
	//		 find a way to forward those
	actualServer := server.NewServer(
		selfServerConn.GetServerVersion(),
		// TODO: pass in the collation id from the server?
		mysql.DEFAULT_COLLATION_ID,
		// flags with some unwanted ones disabled, like upgrade to SSL connection
		capFlags&^(mysql.CLIENT_SSL|mysql.CLIENT_SSL_VERIFY_SERVER_CERT),
	)
	clientSelfConn, err := actualServer.NewConn(
		clientConn,
	)
	if err != nil {
		return fmt.Errorf("failed to accet MySQL client: %w", err)
	}

	p.relayHandler = NewRelayHandler(clientSelfConn, selfServerConn)

	for true {
		err = p.relayHandler.HandleCommand()
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

func getCapabilities(hasCapability func(uint32) bool) uint32 {
	var capabilities uint32
	for i := uint32(0); i < 32; i++ {
		flag := uint32(1 << i)
		if hasCapability(flag) {
			capabilities |= flag
		}
	}
	return capabilities
}
