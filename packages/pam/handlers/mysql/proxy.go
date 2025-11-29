package mysql

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/rs/zerolog/log"
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
	ReadOnlyMode   bool
}

type MysqlProxy struct {
	config       MysqlProxyConfig
	relayHandler *RelayHandler
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
		// smaller version to prevent complex errors
		"8.0.11",
		mysql.DEFAULT_COLLATION_ID,
		mysql.AUTH_NATIVE_PASSWORD,
		nil,
		nil,
	)
	p.relayHandler = NewRelayHandler(selfServerConn, p.config.SessionLogger, p.config)
	clientSelfConn, err := actualServer.NewCustomizedConn(
		clientConn,
		&AnyUserCredentialProvider{},
		p.relayHandler,
	)
	if err != nil {
		return fmt.Errorf("failed to accept MySQL client: %w", err)
	}
	defer func() {
		if !clientSelfConn.Closed() {
			clientSelfConn.Close()
		}
		if !p.relayHandler.Closed() {
			selfServerConn.Close()
		}
	}()

	// if in read-only mode, set the session to be a read-only transaction
	if p.config.ReadOnlyMode {
		if err := p.setSessionReadOnly(selfServerConn); err != nil {
			return err
		}
	}

	for !clientSelfConn.Closed() && !p.relayHandler.Closed() {
		err = clientSelfConn.HandleCommand()
		if err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to handle command")
			return err
		}
	}
	return nil
}

func (p *MysqlProxy) connectToServer() (*client.Conn, error) {
	conn, err := client.Connect(
		p.config.TargetAddr,
		p.config.InjectUsername,
		p.config.InjectPassword,
		p.config.InjectDatabase,
		func(conn *client.Conn) error {
			if p.config.EnableTLS {
				if p.config.TLSConfig == nil {
					return fmt.Errorf("TLS configuration is required when TLS is enabled")
				}
				conn.SetTLSConfig(p.config.TLSConfig)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL server: %w", err)
	}
	return conn, nil
}

func (p *MysqlProxy) setSessionReadOnly(serverConn *client.Conn) error {
	log.Info().Str("sessionID", p.config.SessionID).Msg("Setting session to read-only transaction mode")

	_, err := serverConn.Execute("SET SESSION TRANSACTION READ ONLY;")
	if err != nil {
		log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to set session to read-only mode")
		return fmt.Errorf("failed to set session to read-only: %w", err)
	}

	log.Debug().Str("sessionID", p.config.SessionID).Msg("Session set to read-only successfully")
	return nil
}
