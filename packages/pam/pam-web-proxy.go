package pam

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/kubernetes"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/mysql"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/redis"
	"github.com/Infisical/infisical-merge/packages/pam/handlers/ssh"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"
)

type webHandshakeMessage struct {
	SessionID    string `json:"sessionId"`
	ResourceType string `json:"resourceType"`
	PublicKey    string `json:"publicKey"`
	Signature   string `json:"signature"`
}

type webHandshakeResponse struct {
	PublicKey  string `json:"publicKey"`
	Signature string `json:"signature"`
}

func readLengthPrefixedMessage(conn net.Conn) ([]byte, error) {
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBuf)
	log.Debug().Msgf("[pam-web] readLengthPrefixed: raw length bytes=%x, decoded length=%d", lengthBuf, length)
	if length > 1<<20 {
		return nil, fmt.Errorf("message too large: %d bytes (length prefix bytes: %x)", length, lengthBuf)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("failed to read message body (expected %d bytes): %w", length, err)
	}
	log.Debug().Msgf("[pam-web] readLengthPrefixed: read %d bytes of body", len(data))
	return data, nil
}

func writeLengthPrefixedMessage(conn net.Conn, data []byte) error {
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
	if _, err := conn.Write(lengthBuf); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write message body: %w", err)
	}
	return nil
}

func HandlePAMWebProxy(
	ctx context.Context,
	conn net.Conn,
	httpClient *resty.Client,
	credentialsManager *session.CredentialsManager,
	sessionUploader *session.SessionUploader,
) error {
	// Read browser's ECDH handshake
	msgData, err := readLengthPrefixedMessage(conn)
	if err != nil {
		return fmt.Errorf("[pam-web] failed to read handshake message: %w", err)
	}

	var handshake webHandshakeMessage
	if err := json.Unmarshal(msgData, &handshake); err != nil {
		log.Error().Msgf("[pam-web] Failed to parse handshake JSON (raw first 200 bytes): %s", string(msgData[:min(len(msgData), 200)]))
		return fmt.Errorf("[pam-web] failed to parse handshake message: %w", err)
	}

	log.Info().
		Str("sessionId", handshake.SessionID).
		Str("resourceType", handshake.ResourceType).
		Msg("[pam-web] Received web ECDH handshake")

	browserPubKeyBytes, err := base64.StdEncoding.DecodeString(handshake.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode browser public key: %w", err)
	}

	browserSigBytes, err := base64.StdEncoding.DecodeString(handshake.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode browser signature: %w", err)
	}

	// Fetch credentials + shared secret
	credentials, err := credentialsManager.GetPAMSessionCredentials(handshake.SessionID, time.Now().Add(24*time.Hour))
	if err != nil {
		return fmt.Errorf("[pam-web] failed to retrieve PAM session credentials: %w", err)
	}

	if credentials.SharedSecret == "" {
		return fmt.Errorf("[pam-web] shared secret not available for session %s", handshake.SessionID)
	}

	sharedSecretBytes, err := base64.StdEncoding.DecodeString(credentials.SharedSecret)
	if err != nil {
		return fmt.Errorf("failed to decode shared secret: %w", err)
	}

	// Verify browser's signature -- there are other packages that make this easier but its OK
	mac := hmac.New(sha256.New, sharedSecretBytes)
	mac.Write(browserPubKeyBytes)
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(browserSigBytes, expectedSig) {
		return fmt.Errorf("[pam-web] browser ECDH public key signature verification failed (possible MITM)")
	}

	// Parse browser's ECDH public key
	browserPubKey, err := ecdh.P256().NewPublicKey(browserPubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse browser ECDH public key: %w", err)
	}

	// Generate gateway ECDH keypair
	gatewayPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate gateway ECDH keypair: %w", err)
	}
	gatewayPubKeyBytes := gatewayPrivKey.PublicKey().Bytes()

	// Sign and send gateway's public key
	gwMac := hmac.New(sha256.New, sharedSecretBytes)
	gwMac.Write(gatewayPubKeyBytes)
	gwSig := gwMac.Sum(nil)

	responseMsg := webHandshakeResponse{
		PublicKey:  base64.StdEncoding.EncodeToString(gatewayPubKeyBytes),
		Signature: base64.StdEncoding.EncodeToString(gwSig),
	}

	responseData, err := json.Marshal(responseMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal handshake response: %w", err)
	}

	if err := writeLengthPrefixedMessage(conn, responseData); err != nil {
		return fmt.Errorf("[pam-web] failed to send handshake response: %w", err)
	}

	// Derive AES-256 key via ECDH + HKDF
	sharedECDH, err := gatewayPrivKey.ECDH(browserPubKey)
	if err != nil {
		return fmt.Errorf("failed to compute ECDH shared secret: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, sharedECDH, nil, []byte("infisical-pam-web-encryption"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return fmt.Errorf("failed to derive AES key: %w", err)
	}

	// Create encrypted connection wrapper
	encConn, err := NewEncryptedConn(conn, aesKey)
	if err != nil {
		return fmt.Errorf("failed to create encrypted connection: %w", err)
	}

	log.Info().
		Str("sessionId", handshake.SessionID).
		Str("resourceType", handshake.ResourceType).
		Msg("[pam-web] ECDH handshake completed, AES key derived, encrypted tunnel established")

	// Session expiry monitoring
	timeUntilExpiry := 24 * time.Hour 
	go func() {
		if creds, err := credentialsManager.GetPAMSessionCredentials(handshake.SessionID, time.Now().Add(timeUntilExpiry)); err == nil {
			_ = creds
		}

		timer := time.NewTimer(timeUntilExpiry)
		defer timer.Stop()

		select {
		case <-timer.C:
			log.Info().
				Str("sessionId", handshake.SessionID).
				Msg("PAM web session expired, closing connection")
			if err := sessionUploader.CleanupPAMSession(handshake.SessionID, "expiry"); err != nil {
				log.Error().Err(err).Str("sessionId", handshake.SessionID).Msg("Failed to cleanup PAM web session on expiry")
			}
			encConn.Close()
		case <-ctx.Done():
			return
		}
	}()

	// Session recording setup
	encryptionKey, err := credentialsManager.GetPAMSessionEncryptionKey()
	if err != nil {
		return fmt.Errorf("failed to get PAM session encryption key: %w", err)
	}
	sessionLogger, err := session.NewSessionLogger(handshake.SessionID, encryptionKey, time.Now().Add(timeUntilExpiry), handshake.ResourceType)
	if err != nil {
		return fmt.Errorf("failed to create session logger: %w", err)
	}

	serverName := credentials.Host
	if handshake.ResourceType == session.ResourceTypeKubernetes {
		parsed, parseErr := url.Parse(credentials.Url)
		if parseErr != nil {
			return fmt.Errorf("failed to parse URL: %w", parseErr)
		}
		serverName = parsed.Hostname()
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: !credentials.SSLRejectUnauthorized,
		ServerName:         serverName,
	}
	if credentials.SSLCertificate != "" {
		certPool := x509.NewCertPool()
		if certPool.AppendCertsFromPEM([]byte(credentials.SSLCertificate)) {
			tlsConfig.RootCAs = certPool
		}
	}

	// Route to protocol handler by resource type
	switch handshake.ResourceType {
	case session.ResourceTypePostgres:
		proxyConfig := handlers.PostgresProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      handshake.SessionID,
			SessionLogger:  sessionLogger,
		}
		proxy := handlers.NewPostgresProxy(proxyConfig)
		log.Info().
			Str("sessionId", handshake.SessionID).
			Str("target", proxyConfig.TargetAddr).
			Msg("Starting PostgreSQL PAM web proxy")
		return proxy.HandleConnection(ctx, encConn)

	case session.ResourceTypeMysql:
		mysqlConfig := mysql.MysqlProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			InjectDatabase: credentials.Database,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      handshake.SessionID,
			SessionLogger:  sessionLogger,
		}
		proxy := mysql.NewMysqlProxy(mysqlConfig)
		log.Info().
			Str("sessionId", handshake.SessionID).
			Str("target", mysqlConfig.TargetAddr).
			Msg("Starting MySQL PAM web proxy")
		return proxy.HandleConnection(ctx, encConn)

	case session.ResourceTypeRedis:
		redisConfig := redis.RedisProxyConfig{
			TargetAddr:     fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			InjectUsername: credentials.Username,
			InjectPassword: credentials.Password,
			EnableTLS:      credentials.SSLEnabled,
			TLSConfig:      tlsConfig,
			SessionID:      handshake.SessionID,
			SessionLogger:  sessionLogger,
		}
		proxy := redis.NewRedisProxy(redisConfig)
		log.Info().
			Str("sessionId", handshake.SessionID).
			Str("target", redisConfig.TargetAddr).
			Msg("Starting Redis PAM web proxy")
		return proxy.HandleConnection(ctx, encConn)

	case session.ResourceTypeSSH:
		sshConfig := ssh.SSHProxyConfig{
			TargetAddr:        fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
			AuthMethod:        credentials.AuthMethod,
			InjectUsername:    credentials.Username,
			InjectPassword:    credentials.Password,
			InjectPrivateKey:  credentials.PrivateKey,
			InjectCertificate: credentials.Certificate,
			SessionID:         handshake.SessionID,
			SessionLogger:     sessionLogger,
		}
		proxy := ssh.NewSSHProxy(sshConfig)
		log.Info().
			Str("sessionId", handshake.SessionID).
			Str("target", sshConfig.TargetAddr).
			Msg("Starting SSH PAM web proxy")
		return proxy.HandleConnection(ctx, encConn)

	case session.ResourceTypeKubernetes:
		kubernetesConfig := kubernetes.KubernetesProxyConfig{
			AuthMethod:                credentials.AuthMethod,
			InjectServiceAccountToken: credentials.ServiceAccountToken,
			TargetApiServer:           credentials.Url,
			TLSConfig:                 tlsConfig,
			SessionID:                 handshake.SessionID,
			SessionLogger:             sessionLogger,
		}
		proxy := kubernetes.NewKubernetesProxy(kubernetesConfig)
		log.Info().
			Str("sessionId", handshake.SessionID).
			Str("target", kubernetesConfig.TargetApiServer).
			Msg("Starting Kubernetes PAM web proxy")
		return proxy.HandleConnection(ctx, encConn)

	default:
		return fmt.Errorf("unsupported resource type: %s", handshake.ResourceType)
	}
}
