package pam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/kubernetes"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/mongodb"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/mssql"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/mysql"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/redis"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/ssh"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// MongoProxyGetter returns a session-level MongoDBProxy, creating it on first call.
// This allows the topology to be shared across multiple client connections in the same session.
type MongoProxyGetter func(ctx context.Context, sessionID string, config mongodb.MongoDBProxyConfig) (*mongodb.MongoDBProxy, error)

type GatewayPAMConfig struct {
	SessionId          string
	ResourceType       string
	ExpiryTime         time.Time
	CredentialsManager *session.CredentialsManager
	SessionUploader    *session.SessionUploader
	GetMongoProxy      MongoProxyGetter // Session-level MongoDB proxy sharing
}

type PAMCapabilitiesResponse struct {
	GatewayName            string   `json:"gatewayName"`
	SupportedResourceTypes []string `json:"supportedResourceTypes"`
}

func GetSupportedResourceTypes() []string {
	return []string{
		session.ResourceTypePostgres,
		session.ResourceTypeMysql,
		session.ResourceTypeMssql,
		session.ResourceTypeSSH,
		session.ResourceTypeKubernetes,
		session.ResourceTypeRedis,
		session.ResourceTypeMongodb,
	}
}

// HandlePAMCapabilities handles the capabilities request from the client
func HandlePAMCapabilities(ctx context.Context, conn *tls.Conn, gatewayName string) error {
	response := PAMCapabilitiesResponse{
		GatewayName:            gatewayName,
		SupportedResourceTypes: GetSupportedResourceTypes(),
	}

	data, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal capabilities response")
		return fmt.Errorf("failed to marshal capabilities response: %w", err)
	}

	// Write length prefix (4 bytes) followed by JSON data
	length := uint32(len(data))
	lengthBytes := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := conn.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write capabilities response: %w", err)
	}

	log.Debug().Strs("supportedTypes", response.SupportedResourceTypes).Msg("Sent PAM capabilities to client")
	return nil
}

func HandlePAMCancellation(ctx context.Context, conn *tls.Conn, pamConfig *GatewayPAMConfig, httpClient *resty.Client, cancelSession func(string) bool) error {
	log.Info().Str("sessionId", pamConfig.SessionId).Msg("Received session termination message")

	// Kill the active proxy connection if it exists in the registry
	if cancelled := cancelSession(pamConfig.SessionId); cancelled {
		log.Info().Str("sessionId", pamConfig.SessionId).Msg("Active proxy session cancelled via registry")
	} else {
		log.Info().Str("sessionId", pamConfig.SessionId).Msg("No active proxy session found in registry (may have already ended)")
	}

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
	sessionLogger, err := session.NewSessionLogger(pamConfig.SessionId, encryptionKey, pamConfig.ExpiryTime, pamConfig.ResourceType)
	if err != nil {
		return fmt.Errorf("failed to create session logger: %w", err)
	}
	defer func() {
		if err := sessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionId", pamConfig.SessionId).Msg("Failed to close session logger")
		}
	}()
	pamConfig.SessionUploader.RegisterSession(pamConfig.SessionId)

	serverName := credentials.Host
	switch pamConfig.ResourceType {
	case session.ResourceTypeKubernetes:
		parsed, err := url.Parse(credentials.Url)
		if err != nil {
			return fmt.Errorf("failed to parse URL: %w", err)
		}
		serverName = parsed.Hostname()
	case session.ResourceTypeMongodb:
		// For MongoDB, don't set ServerName — the driver's topology sets it
		// correctly per server (each replica set member has its own hostname).
		// The Host field may be a URI, a bare SRV hostname, or host:port,
		// none of which are valid TLS server names.
		serverName = ""
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: !credentials.SSLRejectUnauthorized,
		ServerName:         serverName,
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
	case session.ResourceTypePostgres:
		proxyConfig := handlers.PostgresProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      pamConfig.SessionId,
			SessionLogger:  sessionLogger,
		}
		proxy := handlers.NewPostgresProxy(proxyConfig)
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", proxyConfig.TargetAddr).
			Bool("sslEnabled", credentials.SSLEnabled).
			Msg("Starting PostgreSQL PAM proxy")
		return proxy.HandleConnection(ctx, conn)
	case session.ResourceTypeMysql:
		mysqlConfig := mysql.MysqlProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      pamConfig.SessionId,
			SessionLogger:  sessionLogger,
		}

		proxy := mysql.NewMysqlProxy(mysqlConfig)
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", mysqlConfig.TargetAddr).
			Bool("sslEnabled", credentials.SSLEnabled).
			Msg("Starting MySQL PAM proxy")
		return proxy.HandleConnection(ctx, conn)
	case session.ResourceTypeMssql:
		mssqlConfig := mssql.MssqlProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      pamConfig.SessionId,
			SessionLogger:  sessionLogger,
		}

		proxy := mssql.NewMssqlProxy(mssqlConfig)
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", mssqlConfig.TargetAddr).
			Bool("sslEnabled", credentials.SSLEnabled).
			Msg("Starting MSSQL PAM proxy")
		return proxy.HandleConnection(ctx, conn)
	case session.ResourceTypeRedis:
		redisConfig := redis.RedisProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      pamConfig.SessionId,
			SessionLogger:  sessionLogger,
		}

		proxy := redis.NewRedisProxy(redisConfig)
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", redisConfig.TargetAddr).
			Bool("sslEnabled", credentials.SSLEnabled).
			Msg("Starting Redis PAM proxy")
		return proxy.HandleConnection(ctx, conn)
	case session.ResourceTypeSSH:
		sshConfig := ssh.SSHProxyConfig{
			TargetAddr:        fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			AuthMethod:        credentials.AuthMethod,
			InjectUsername:    credentials.Username,
			InjectPassword:    credentials.Password,
			InjectPrivateKey:  credentials.PrivateKey,
			InjectCertificate: credentials.Certificate,
			SessionID:         pamConfig.SessionId,
			SessionLogger:     sessionLogger,
		}
		proxy := ssh.NewSSHProxy(sshConfig)
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", sshConfig.TargetAddr).
			Msg("Starting SSH PAM proxy")

		return proxy.HandleConnection(ctx, conn)
	case session.ResourceTypeKubernetes:
		kubernetesConfig := kubernetes.KubernetesProxyConfig{
			AuthMethod:                credentials.AuthMethod,
			InjectServiceAccountToken: credentials.ServiceAccountToken,
			TargetApiServer:           credentials.Url,
			TLSConfig:                 tlsConfig,
			SessionID:                 pamConfig.SessionId,
			SessionLogger:             sessionLogger,
		}

		// For gateway-kubernetes-auth, override target URL and TLS with pod's in-cluster credentials
		if credentials.AuthMethod == "gateway-kubernetes-auth" {
			kubernetesConfig.ImpersonateNamespace = credentials.Namespace
			kubernetesConfig.ImpersonateServiceAccount = credentials.ServiceAccountName
			if credentials.Namespace == "" || credentials.ServiceAccountName == "" {
				return fmt.Errorf("gateway-kubernetes-auth requires non-empty namespace and service account name")
			}

			// Auto-discover K8s API URL from env vars
			host, port := os.Getenv(util.KUBERNETES_SERVICE_HOST_ENV_NAME), os.Getenv(util.KUBERNETES_SERVICE_PORT_HTTPS_ENV_NAME)
			if host == "" || port == "" {
				return fmt.Errorf("gateway-kubernetes-auth requires KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT_HTTPS to be set; gateway must run inside a Kubernetes pod")
			}
			kubernetesConfig.TargetApiServer = fmt.Sprintf("https://%s", net.JoinHostPort(host, port))

			// Use pod's in-cluster CA cert with strict TLS (ignore resource SSL settings)
			caCert, err := os.ReadFile(util.KUBERNETES_SERVICE_ACCOUNT_CA_CERT_PATH)
			if err != nil {
				return fmt.Errorf("gateway-kubernetes-auth: failed to read pod CA cert for strict TLS: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("gateway-kubernetes-auth: pod CA cert PEM is invalid or empty; cannot establish strict TLS")
			}
			kubernetesConfig.TLSConfig = &tls.Config{
				RootCAs: caCertPool,
			}
		}

		proxy := kubernetes.NewKubernetesProxy(kubernetesConfig)
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("target", kubernetesConfig.TargetApiServer).
			Str("authMethod", credentials.AuthMethod).
			Msg("Starting Kubernetes PAM proxy")
		return proxy.HandleConnection(ctx, conn)
	case session.ResourceTypeMongodb:
		mongoConfig := mongodb.MongoDBProxyConfig{
			Host:           credentials.ConnectionString,
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      pamConfig.SessionId,
		}
		log.Info().
			Str("sessionId", pamConfig.SessionId).
			Str("connectionString", credentials.ConnectionString).
			Bool("sslEnabled", credentials.SSLEnabled).
			Msg("Starting MongoDB PAM proxy")

		// Get or create session-level proxy (shared across connections).
		// The topology is created once on the first connection and reused
		// for subsequent connections, avoiding per-connection SRV/TLS/SCRAM overhead.
		proxy, err := pamConfig.GetMongoProxy(ctx, pamConfig.SessionId, mongoConfig)
		if err != nil {
			return fmt.Errorf("MongoDB proxy init: %w", err)
		}

		return proxy.HandleConnection(ctx, conn, sessionLogger)
	default:
		return fmt.Errorf("unsupported resource type: %s", pamConfig.ResourceType)
	}
}
