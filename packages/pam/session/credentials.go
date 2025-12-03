package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type PAMCredentials struct {
	AuthMethod            string
	Username              string
	Password              string
	Database              string
	PrivateKey            string
	Host                  string
	Port                  int
	SSLEnabled            bool
	SSLRejectUnauthorized bool
	SSLCertificate        string
	ServiceAccountToken   string
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
}

func NewCredentialsManager(httpClient *resty.Client) *CredentialsManager {
	return &CredentialsManager{
		httpClient:       httpClient,
		credentialsCache: make(map[string]*cachedCredentials),
		stopCleanup:      make(chan struct{}),
	}
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
		PrivateKey:            response.Credentials.PrivateKey,
		Host:                  response.Credentials.Host,
		Port:                  response.Credentials.Port,
		SSLEnabled:            response.Credentials.SSLEnabled,
		SSLRejectUnauthorized: response.Credentials.SSLRejectUnauthorized,
		SSLCertificate:        response.Credentials.SSLCertificate,
	}

	cm.cacheMutex.Lock()
	cm.credentialsCache[sessionId] = &cachedCredentials{
		credentials: credentials,
		expiresAt:   expiryTime,
	}
	cm.cacheMutex.Unlock()

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
}

func (cm *CredentialsManager) CleanupSessionCredentials(sessionID string) {
	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()

	if _, exists := cm.credentialsCache[sessionID]; exists {
		delete(cm.credentialsCache, sessionID)
		log.Debug().Str("sessionId", sessionID).Msg("Cleaned up cached PAM session credentials")
	}
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

	// Clear all cached credentials
	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()

	for sessionId := range cm.credentialsCache {
		delete(cm.credentialsCache, sessionId)
	}

	// Clear encryption key
	cm.sessionEncryptionKey = ""

	log.Debug().Msg("PAM credentials manager shutdown complete")
}
