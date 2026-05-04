package session

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

func uploadTokenFilePath(sessionID string) string {
	return filepath.Join(GetSessionRecordingDir(), "chunks", sessionID+".uploadtoken.enc")
}

type PAMCredentials struct {
	AuthMethod            string
	Username              string
	Password              string
	Database              string
	ConnectionString      string // MongoDB: full URI (mongodb[+srv]://...)
	PrivateKey            string
	Certificate           string
	Host                  string
	Port                  int
	SSLEnabled            bool
	SSLRejectUnauthorized bool
	SSLCertificate        string
	Url                   string
	ServiceAccountToken   string
	ServiceAccountName    string
	Namespace             string
	PolicyRules           *api.PAMPolicyRules
}

type PAMRecordingSecrets struct {
	SessionKey     []byte // 32 bytes, AES-256 key
	UploadToken    string // base64-encoded 32 bytes
	StorageBackend string // "postgres" or "aws-s3"
	ProjectId      string
	SessionId      string
}

type cachedCredentials struct {
	credentials *PAMCredentials
	expiresAt   time.Time
}

// CredentialsManager encapsulates credential caching with proper lifecycle management
type CredentialsManager struct {
	httpClient           *resty.Client
	credentialsCache     map[string]*cachedCredentials
	cacheMutex           sync.RWMutex
	sessionEncryptionKey string
	cleanupOnce          sync.Once
	cleanupTicker        *time.Ticker
	stopCleanup          chan struct{}

	recordingSecrets   map[string]*PAMRecordingSecrets
	recordingSecretsMu sync.RWMutex
}

func NewCredentialsManager(httpClient *resty.Client) *CredentialsManager {
	return &CredentialsManager{
		httpClient:       httpClient,
		credentialsCache: make(map[string]*cachedCredentials),
		stopCleanup:      make(chan struct{}),
		recordingSecrets: make(map[string]*PAMRecordingSecrets),
	}
}

func (cm *CredentialsManager) GetRecordingSecrets(sessionId string) *PAMRecordingSecrets {
	cm.recordingSecretsMu.RLock()
	defer cm.recordingSecretsMu.RUnlock()
	return cm.recordingSecrets[sessionId]
}

func (cm *CredentialsManager) persistUploadToken(sessionID, uploadToken string) {
	encryptionKey, err := cm.GetPAMSessionEncryptionKey()
	if err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to get encryption key for upload token persistence")
		return
	}
	encrypted, err := EncryptData([]byte(uploadToken), encryptionKey)
	if err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to encrypt upload token")
		return
	}
	path := uploadTokenFilePath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to create dir for upload token")
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encrypted, 0o600); err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to write upload token file")
		return
	}
	_ = os.Rename(tmp, path)
}

func (cm *CredentialsManager) LoadRecordingSecretsFromDisk(sessionID string) {
	path := uploadTokenFilePath(sessionID)
	encrypted, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to read persisted upload token")
		}
		return
	}
	encryptionKey, err := cm.GetPAMSessionEncryptionKey()
	if err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to get encryption key for upload token decryption")
		return
	}
	decrypted, err := DecryptData(encrypted, encryptionKey)
	if err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to decrypt persisted upload token")
		return
	}
	cm.recordingSecretsMu.Lock()
	cm.recordingSecrets[sessionID] = &PAMRecordingSecrets{
		UploadToken: string(decrypted),
		SessionId:   sessionID,
	}
	cm.recordingSecretsMu.Unlock()
	log.Info().Str("sessionId", sessionID).Msg("Restored recording upload token from disk")
}

func deletePersistedUploadToken(sessionID string) {
	_ = os.Remove(uploadTokenFilePath(sessionID))
}

// startCleanupRoutine starts the background cleanup routine for expired credentials
func (cm *CredentialsManager) startCleanupRoutine() {
	cm.cleanupTicker = time.NewTicker(1 * time.Minute)
	go func() {
		defer cm.cleanupTicker.Stop()

		for {
			select {
			case <-cm.cleanupTicker.C:
				cm.cleanupExpiredCredentials()
			case <-cm.stopCleanup:
				return
			}
		}
	}()
	log.Debug().Msg("Started PAM credentials cleanup routine")
}

func (cm *CredentialsManager) GetPAMSessionCredentials(sessionId string, expiryTime time.Time) (*PAMCredentials, error) {
	cm.cleanupOnce.Do(cm.startCleanupRoutine)

	cm.cacheMutex.RLock()
	cached, exists := cm.credentialsCache[sessionId]
	cm.cacheMutex.RUnlock()

	if exists && time.Now().Before(cached.expiresAt) {
		return cached.credentials, nil
	}

	response, err := api.CallPAMSessionCredentials(cm.httpClient, sessionId)
	if err != nil {
		return nil, fmt.Errorf("failed to call PAM session credentials API: %w", err)
	}

	credentials := &PAMCredentials{
		AuthMethod:            response.Credentials.AuthMethod,
		Username:              response.Credentials.Username,
		Password:              response.Credentials.Password,
		Database:              response.Credentials.Database,
		ConnectionString:      response.Credentials.ConnectionString,
		PrivateKey:            response.Credentials.PrivateKey,
		Certificate:           response.Credentials.Certificate,
		Host:                  response.Credentials.Host,
		Port:                  response.Credentials.Port,
		SSLEnabled:            response.Credentials.SSLEnabled,
		SSLRejectUnauthorized: response.Credentials.SSLRejectUnauthorized,
		SSLCertificate:        response.Credentials.SSLCertificate,
		Url:                   response.Credentials.Url,
		ServiceAccountToken:   response.Credentials.ServiceAccountToken,
		ServiceAccountName:    response.Credentials.ServiceAccountName,
		Namespace:             response.Credentials.Namespace,
		PolicyRules:           response.PolicyRules,
	}

	cm.cacheMutex.Lock()
	cm.credentialsCache[sessionId] = &cachedCredentials{
		credentials: credentials,
		expiresAt:   expiryTime,
	}
	cm.cacheMutex.Unlock()

	if response.Recording != nil && response.Recording.SessionKey != "" {
		decoded, decodeErr := base64.StdEncoding.DecodeString(response.Recording.SessionKey)
		if decodeErr != nil {
			log.Error().Err(decodeErr).Str("sessionId", sessionId).Msg("Failed to decode session recording key")
		} else {
			uploadToken := response.Recording.UploadToken

			cm.recordingSecretsMu.Lock()
			if uploadToken == "" {
				if existing := cm.recordingSecrets[sessionId]; existing != nil {
					uploadToken = existing.UploadToken
				}
			}
			cm.recordingSecrets[sessionId] = &PAMRecordingSecrets{
				SessionKey:     decoded,
				UploadToken:    uploadToken,
				StorageBackend: response.Recording.StorageBackend,
				ProjectId:      response.Recording.ProjectId,
				SessionId:      response.Recording.SessionId,
			}
			cm.recordingSecretsMu.Unlock()

			if response.Recording.UploadToken != "" {
				cm.persistUploadToken(sessionId, response.Recording.UploadToken)
			}
			log.Debug().
				Str("sessionId", sessionId).
				Str("storageBackend", response.Recording.StorageBackend).
				Msg("Cached PAM session recording secrets")
		}
	}

	return credentials, nil
}

func (cm *CredentialsManager) cleanupExpiredCredentials() {
	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()

	now := time.Now()
	for sessionId, cached := range cm.credentialsCache {
		if now.After(cached.expiresAt) {
			delete(cm.credentialsCache, sessionId)
			log.Debug().Str("sessionId", sessionId).Msg("Removed expired PAM session credentials from cache")
		}
	}
	// Recording secrets are intentionally NOT cleaned here. They may still be needed by pending chunks that haven't been uploaded yet (e.g. during an S3 outage)
	// They are cleaned by CleanupSessionCredentials (called from CleanupPAMSession) or by Shutdown
}

func (cm *CredentialsManager) CleanupSessionCredentials(sessionID string) {
	cm.cacheMutex.Lock()
	if _, exists := cm.credentialsCache[sessionID]; exists {
		delete(cm.credentialsCache, sessionID)
		log.Debug().Str("sessionId", sessionID).Msg("Cleaned up cached PAM session credentials")
	}
	cm.cacheMutex.Unlock()

	cm.recordingSecretsMu.Lock()
	if _, exists := cm.recordingSecrets[sessionID]; exists {
		delete(cm.recordingSecrets, sessionID)
		log.Debug().Str("sessionId", sessionID).Msg("Cleared PAM session recording secrets from memory")
	}
	cm.recordingSecretsMu.Unlock()

	deletePersistedUploadToken(sessionID)
}

func (cm *CredentialsManager) GetPAMSessionEncryptionKey() (string, error) {
	cm.cacheMutex.RLock()
	if cm.sessionEncryptionKey != "" {
		key := cm.sessionEncryptionKey
		cm.cacheMutex.RUnlock()
		return key, nil
	}
	cm.cacheMutex.RUnlock()

	key, err := api.CallGetPamSessionKey(cm.httpClient)
	if err != nil {
		return "", fmt.Errorf("failed to get PAM session encryption key: %w", err)
	}

	cm.cacheMutex.Lock()
	cm.sessionEncryptionKey = key
	cm.cacheMutex.Unlock()

	return key, nil
}

func (cm *CredentialsManager) Shutdown() {
	close(cm.stopCleanup)

	cm.cacheMutex.Lock()
	for sessionId := range cm.credentialsCache {
		delete(cm.credentialsCache, sessionId)
	}
	cm.sessionEncryptionKey = ""
	cm.cacheMutex.Unlock()

	cm.recordingSecretsMu.Lock()
	for sessionId := range cm.recordingSecrets {
		delete(cm.recordingSecrets, sessionId)
	}
	cm.recordingSecretsMu.Unlock()

	log.Debug().Msg("PAM credentials manager shutdown complete")
}
