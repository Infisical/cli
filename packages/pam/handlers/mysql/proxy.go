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
	"strings"
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

	// TODO: this is a bit silly that we need to parse the cap flags
	//	     we should create PR in the upstream to expose the Capability uint32 value
	//	     directly
	capFlagsString := selfServerConn.CapabilityString()
	log.Info().Str("sessionID", sessionID).Msgf("Connected to target server %s, server_version=%s, capability=%s", p.config.TargetAddr, selfServerConn.GetServerVersion(), capFlagsString)
	capFlags, err := parseCapabilityString(capFlagsString)
	if err != nil {
		log.Error().Err(err).
			Str("sessionID", sessionID).
			Msgf("Failed to parse CapabilityString %s from MySQL server", selfServerConn.CapabilityString())
		return fmt.Errorf("failed to connect to MySQL server: %w", err)
	}
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
	// TODO: where did the original code do this? why we need this?
	selfServerConn.ResetSequence()

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

func parseCapabilityString(capStr string) (uint32, error) {
	if capStr == "" {
		return 0, nil
	}

	var capability uint32
	caps := strings.Split(capStr, "|")

	for _, cap := range caps {
		switch cap {
		case "CLIENT_LONG_PASSWORD":
			capability |= mysql.CLIENT_LONG_PASSWORD
		case "CLIENT_FOUND_ROWS":
			capability |= mysql.CLIENT_FOUND_ROWS
		case "CLIENT_LONG_FLAG":
			capability |= mysql.CLIENT_LONG_FLAG
		case "CLIENT_CONNECT_WITH_DB":
			capability |= mysql.CLIENT_CONNECT_WITH_DB
		case "CLIENT_NO_SCHEMA":
			capability |= mysql.CLIENT_NO_SCHEMA
		case "CLIENT_COMPRESS":
			capability |= mysql.CLIENT_COMPRESS
		case "CLIENT_ODBC":
			capability |= mysql.CLIENT_ODBC
		case "CLIENT_LOCAL_FILES":
			capability |= mysql.CLIENT_LOCAL_FILES
		case "CLIENT_IGNORE_SPACE":
			capability |= mysql.CLIENT_IGNORE_SPACE
		case "CLIENT_PROTOCOL_41":
			capability |= mysql.CLIENT_PROTOCOL_41
		case "CLIENT_INTERACTIVE":
			capability |= mysql.CLIENT_INTERACTIVE
		case "CLIENT_SSL":
			capability |= mysql.CLIENT_SSL
		case "CLIENT_IGNORE_SIGPIPE":
			capability |= mysql.CLIENT_IGNORE_SIGPIPE
		case "CLIENT_TRANSACTIONS":
			capability |= mysql.CLIENT_TRANSACTIONS
		case "CLIENT_RESERVED":
			capability |= mysql.CLIENT_RESERVED
		case "CLIENT_SECURE_CONNECTION":
			capability |= mysql.CLIENT_SECURE_CONNECTION
		case "CLIENT_MULTI_STATEMENTS":
			capability |= mysql.CLIENT_MULTI_STATEMENTS
		case "CLIENT_MULTI_RESULTS":
			capability |= mysql.CLIENT_MULTI_RESULTS
		case "CLIENT_PS_MULTI_RESULTS":
			capability |= mysql.CLIENT_PS_MULTI_RESULTS
		case "CLIENT_PLUGIN_AUTH":
			capability |= mysql.CLIENT_PLUGIN_AUTH
		case "CLIENT_CONNECT_ATTRS":
			capability |= mysql.CLIENT_CONNECT_ATTRS
		case "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA":
			capability |= mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
		case "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS":
			capability |= mysql.CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
		case "CLIENT_SESSION_TRACK":
			capability |= mysql.CLIENT_SESSION_TRACK
		case "CLIENT_DEPRECATE_EOF":
			capability |= mysql.CLIENT_DEPRECATE_EOF
		case "CLIENT_OPTIONAL_RESULTSET_METADATA":
			capability |= mysql.CLIENT_OPTIONAL_RESULTSET_METADATA
		case "CLIENT_ZSTD_COMPRESSION_ALGORITHM":
			capability |= mysql.CLIENT_ZSTD_COMPRESSION_ALGORITHM
		case "CLIENT_QUERY_ATTRIBUTES":
			capability |= mysql.CLIENT_QUERY_ATTRIBUTES
		case "MULTI_FACTOR_AUTHENTICATION":
			capability |= mysql.MULTI_FACTOR_AUTHENTICATION
		case "CLIENT_CAPABILITY_EXTENSION":
			capability |= mysql.CLIENT_CAPABILITY_EXTENSION
		case "CLIENT_SSL_VERIFY_SERVER_CERT":
			capability |= mysql.CLIENT_SSL_VERIFY_SERVER_CERT
		case "CLIENT_REMEMBER_OPTIONS":
			capability |= mysql.CLIENT_REMEMBER_OPTIONS
		default:
			var field uint32
			_, err := fmt.Sscanf(cap, "(%d)", &field)
			if err != nil {
				return 0, fmt.Errorf("invalid capability: %s", cap)
			}
			capability |= field
		}
	}

	return capability, nil
}
