package pam

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type GatewayPAMConfig struct {
	SessionId    string
	ResourceType string
	ExpiryTime   time.Time
}

func HandlePAMCancellation(ctx context.Context, conn *tls.Conn, pamConfig *GatewayPAMConfig, httpClient *resty.Client) error {
	log.Info().Str("sessionId", pamConfig.SessionId).Msg("Received session termination message")

	if err := session.CleanupPAMSession(pamConfig.SessionId, httpClient, "cancellation"); err != nil {
		log.Error().Err(err).Str("sessionId", pamConfig.SessionId).Msg("Failed to cleanup PAM session")
	}

	conn.Close()

	return nil
}

func HandlePAMProxy(ctx context.Context, conn *tls.Conn, pamConfig *GatewayPAMConfig, httpClient *resty.Client) error {
	credentials, err := session.GetPAMSessionCredentials(pamConfig.SessionId, pamConfig.ExpiryTime, httpClient)
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

				if err := session.CleanupPAMSession(pamConfig.SessionId, httpClient, "expiry"); err != nil {
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

			if err := session.CleanupPAMSession(pamConfig.SessionId, httpClient, "already_expired"); err != nil {
				log.Error().Err(err).Str("sessionId", pamConfig.SessionId).Msg("Failed to cleanup already expired PAM session")
			}

			conn.Close()
		}
	}()

	if pamConfig.ResourceType != "postgres" {
		return fmt.Errorf("unsupported resource type: %s", pamConfig.ResourceType)
	}

	if pamConfig.ResourceType == "postgres" {
		encryptionKey, err := session.GetPAMSessionEncryptionKey(httpClient)
		if err != nil {
			return fmt.Errorf("failed to get PAM session encryption key: %w", err)
		}

		proxyConfig := handlers.PostgresProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: !credentials.SSLRejectUnauthorized,
			},
			SessionID:     pamConfig.SessionId,
			EncryptionKey: encryptionKey,
			ExpiresAt:     pamConfig.ExpiryTime,
		}

		proxy, err := handlers.NewPostgresProxy(proxyConfig)
		if err != nil {
			return fmt.Errorf("failed to create PostgreSQL proxy: %w", err)
		}

		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", proxyConfig.TargetAddr).
			Str("username", credentials.Username).
			Str("database", credentials.Database).
			Bool("sslEnabled", credentials.SSLEnabled).
			Msg("Starting PostgreSQL PAM proxy")

		return proxy.HandleConnection(ctx, conn)
	}

	return nil
}
