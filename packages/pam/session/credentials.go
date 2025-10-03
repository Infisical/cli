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
	Username              string
	Password              string
	Database              string
	Host                  string
	Port                  int
	SSLEnabled            bool
	SSLRejectUnauthorized bool
	SSLCertificate        string
}

type cachedCredentials struct {
	credentials *PAMCredentials
	expiresAt   time.Time
}

var (
	credentialsCache = make(map[string]*cachedCredentials)
	cacheMutex       sync.RWMutex
	cleanupOnce      sync.Once
)

var sessionEncryptionKey string

func startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			cleanupExpiredCredentials()
		}
	}()
	log.Debug().Msg("Started PAM credentials cleanup routine")
}

func GetPAMSessionCredentials(sessionId string, expiryTime time.Time, httpClient *resty.Client) (*PAMCredentials, error) {
	cleanupOnce.Do(startCleanupRoutine)

	cacheMutex.RLock()
	cached, exists := credentialsCache[sessionId]
	cacheMutex.RUnlock()

	if exists && time.Now().Before(cached.expiresAt) {
		return cached.credentials, nil
	}

	response, err := api.CallPAMSessionCredentials(httpClient, sessionId)
	if err != nil {
		return nil, fmt.Errorf("failed to call PAM session credentials API: %w", err)
	}

	credentials := &PAMCredentials{
		Username:              response.Credentials.Username,
		Password:              response.Credentials.Password,
		Database:              response.Credentials.Database,
		Host:                  response.Credentials.Host,
		Port:                  response.Credentials.Port,
		SSLEnabled:            response.Credentials.SSLEnabled,
		SSLRejectUnauthorized: response.Credentials.SSLRejectUnauthorized,
		SSLCertificate:        response.Credentials.SSLCertificate,
	}

	cacheMutex.Lock()
	credentialsCache[sessionId] = &cachedCredentials{
		credentials: credentials,
		expiresAt:   expiryTime,
	}
	cacheMutex.Unlock()

	return credentials, nil
}

func cleanupExpiredCredentials() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	now := time.Now()
	for sessionId, cached := range credentialsCache {
		if now.After(cached.expiresAt) {
			delete(credentialsCache, sessionId)
			log.Debug().Str("sessionId", sessionId).Msg("Removed expired PAM session credentials from cache")
		}
	}
}

func CleanupSessionCredentials(sessionID string) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if _, exists := credentialsCache[sessionID]; exists {
		delete(credentialsCache, sessionID)
		log.Debug().Str("sessionId", sessionID).Msg("Cleaned up cached PAM session credentials")
	}
}

func GetPAMSessionEncryptionKey(httpClient *resty.Client) (string, error) {
	if sessionEncryptionKey != "" {
		return sessionEncryptionKey, nil
	}

	key, err := api.CallGetPamSessionKey(httpClient)
	if err != nil {
		return "", fmt.Errorf("failed to get PAM session encryption key: %w", err)
	}

	sessionEncryptionKey = key

	return sessionEncryptionKey, nil
}
