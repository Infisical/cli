package pam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/mysql"

	"github.com/Infisical/infisical-merge/packages/pam/handlers"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	ResourceTypePostgres = "postgres"
	ResourceTypeMysql    = "mysql"
)

type GatewayPAMConfig struct {
	SessionId          string
	ResourceType       string
	ExpiryTime         time.Time
	CredentialsManager *session.CredentialsManager
	SessionUploader    *session.SessionUploader
}

func HandlePAMCancellation(ctx context.Context, conn *tls.Conn, pamConfig *GatewayPAMConfig, httpClient *resty.Client) error {
	log.Info().Str("sessionId", pamConfig.SessionId).Msg("Received session termination message")

	if err := pamConfig.SessionUploader.CleanupPAMSession(pamConfig.SessionId, "cancellation"); err != nil {
		log.Error().Err(err).Str("sessionId", pamConfig.SessionId).Msg("Failed to cleanup PAM session")
	}

	conn.Close()

	return nil
}

func HandlePAMProxy(ctx context.Context, conn *tls.Conn, pamConfig *GatewayPAMConfig, httpClient *resty.Client) error {
	credentials, err := pamConfig.CredentialsManager.GetPAMSessionCredentials(pamConfig.SessionId, pamConfig.ExpiryTime)
	if err != nil {
		log.Error().Err(err).Str("sessionId", pamConfig.SessionId).Msg("Failed to retrieve PAM session credentials")
		return fmt.Errorf("failed to retrieve PAM session credentials: %w", err)
	}

	// Start a goroutine to monitor session expiry and close connection when exceeded
	go func() {
		timeUntilExpiry := time.Until(pamConfig.ExpiryTime)
		if timeUntilExpiry > 0 {
			timer := time.NewTimer(timeUntilExpiry)
			defer timer.Stop()

			select {
			case <-timer.C:
				log.Info().
					Str("sessionId", pamConfig.SessionId).
					Str("resourceType", pamConfig.ResourceType).
					Time("expiryTime", pamConfig.ExpiryTime).
					Msg("PAM session expired, closing connection")

				if err := pamConfig.SessionUploader.CleanupPAMSession(pamConfig.SessionId, "expiry"); err != nil {
					log.Error().Err(err).Str("sessionId", pamConfig.SessionId).Msg("Failed to cleanup PAM session on expiry")
				}

				conn.Close()
			case <-ctx.Done():
				// Context cancelled, exit gracefully
				return
			}
		} else {
			log.Info().
				Str("sessionId", pamConfig.SessionId).
				Str("resourceType", pamConfig.ResourceType).
				Time("expiryTime", pamConfig.ExpiryTime).
				Msg("PAM session already expired, closing connection immediately")

			if err := pamConfig.SessionUploader.CleanupPAMSession(pamConfig.SessionId, "already_expired"); err != nil {
				log.Error().Err(err).Str("sessionId", pamConfig.SessionId).Msg("Failed to cleanup already expired PAM session")
			}

			conn.Close()
		}
	}()

	encryptionKey, err := pamConfig.CredentialsManager.GetPAMSessionEncryptionKey()
	if err != nil {
		return fmt.Errorf("failed to get PAM session encryption key: %w", err)
	}
	sessionLogger, err := session.NewSessionLogger(pamConfig.SessionId, encryptionKey, pamConfig.ExpiryTime)
	if err != nil {
		return fmt.Errorf("failed to create session logger: %w", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: !credentials.SSLRejectUnauthorized,
		ServerName:         credentials.Host,
	}
	// If a server certificate is provided, add it to the root CA pool
	if credentials.SSLCertificate != "" {
		certPool := x509.NewCertPool()
		if certPool.AppendCertsFromPEM([]byte(credentials.SSLCertificate)) {
			tlsConfig.RootCAs = certPool
			log.Debug().
				Str("sessionId", pamConfig.SessionId).
				Msg("Using provided server certificate for TLS connection")
		} else {
			log.Warn().
				Str("sessionId", pamConfig.SessionId).
				Msg("Failed to parse provided server certificate, falling back to default behavior")
		}
	}

	switch pamConfig.ResourceType {
	case ResourceTypePostgres:
		proxyConfig := handlers.PostgresProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      pamConfig.SessionId,
			SessionLogger:  sessionLogger,
			ReadOnlyMode:   credentials.ReadOnlyMode,
		}
		proxy := handlers.NewPostgresProxy(proxyConfig)
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", proxyConfig.TargetAddr).
			Bool("sslEnabled", credentials.SSLEnabled).
			Msg("Starting PostgreSQL PAM proxy")
		return proxy.HandleConnection(ctx, conn)
	case ResourceTypeMysql:
		mysqlConfig := mysql.MysqlProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      pamConfig.SessionId,
			SessionLogger:  sessionLogger,
			ReadOnlyMode:   credentials.ReadOnlyMode,
		}

		proxy := mysql.NewMysqlProxy(mysqlConfig)
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", mysqlConfig.TargetAddr).
			Bool("sslEnabled", credentials.SSLEnabled).
			Msg("Starting MySQL PAM proxy")
		return proxy.HandleConnection(ctx, conn)
	default:
		return fmt.Errorf("unsupported resource type: %s", pamConfig.ResourceType)
	}
}
