package session

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type sessionMutexInfo struct {
	mutex     *sync.Mutex
	expiresAt time.Time
}

type SessionLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Input     string    `json:"input"`
	Output    string    `json:"output"`
}

type SessionLogger struct {
	sessionID     string
	encryptionKey string
	expiresAt     time.Time
	file          *os.File
	mutex         sync.Mutex
}

type RequestResponsePair struct {
	Timestamp time.Time `json:"timestamp"`
	Input     string    `json:"input"`
	Output    string    `json:"output"`
}

var (
	sessionMutexes     = make(map[string]*sessionMutexInfo)
	sessionMutexLock   sync.RWMutex
	sessionCleanupOnce sync.Once

	globalSessionRecordingPath string
)

func SetSessionRecordingPath(path string) {
	globalSessionRecordingPath = path
}

func GetSessionRecordingDir() string {
	if globalSessionRecordingPath != "" {
		return globalSessionRecordingPath
	}
	return "/var/lib/infisical/session_recordings"
}

// This ensures atomic writes across concurrent connections for the same session
func getSessionMutex(sessionID string, expiresAt time.Time) *sync.Mutex {
	sessionMutexLock.RLock()
	info, exists := sessionMutexes[sessionID]
	sessionMutexLock.RUnlock()

	if exists {
		return info.mutex
	}

	// Need to create a new mutex
	sessionMutexLock.Lock()
	defer sessionMutexLock.Unlock()

	// Double-check in case another goroutine created it while we were waiting
	if info, exists := sessionMutexes[sessionID]; exists {
		return info.mutex
	}

	// Create new mutex and info for this session
	info = &sessionMutexInfo{
		mutex:     &sync.Mutex{},
		expiresAt: expiresAt,
	}
	sessionMutexes[sessionID] = info

	// Start the cleanup goroutine on first session creation
	sessionCleanupOnce.Do(startSessionCleanupRoutine)

	return info.mutex
}

func startSessionCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
		defer ticker.Stop()

		for range ticker.C {
			cleanupExpiredSessions()
		}
	}()
}

func cleanupExpiredSessions() {
	now := time.Now()

	sessionMutexLock.RLock()
	expiredSessions := make([]string, 0)
	for sessionID, info := range sessionMutexes {
		if now.After(info.expiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}
	sessionMutexLock.RUnlock()

	for _, sessionID := range expiredSessions {
		sessionMutexLock.Lock()
		delete(sessionMutexes, sessionID)
		sessionMutexLock.Unlock()
	}
}

func CleanupSessionMutex(sessionID string) {
	sessionMutexLock.Lock()
	defer sessionMutexLock.Unlock()

	if _, exists := sessionMutexes[sessionID]; exists {
		delete(sessionMutexes, sessionID)
		log.Debug().Str("sessionId", sessionID).Msg("Cleaned up session mutex")
	}
}

func NewSessionLogger(sessionID string, encryptionKey string, expiresAt time.Time) (*SessionLogger, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}
	if encryptionKey == "" {
		return nil, fmt.Errorf("encryption key cannot be empty")
	}

	recordingDir := GetSessionRecordingDir()
	// Ensure the directory exists
	if err := os.MkdirAll(recordingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session recording directory: %w", err)
	}

	filename := fmt.Sprintf("pam_session_%s_expires_%d.enc", sessionID, expiresAt.Unix())
	fullPath := filepath.Join(recordingDir, filename)

	// Open file in append mode to support multiple connections per session
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open session file: %w", err)
	}

	return &SessionLogger{
		sessionID:     sessionID,
		encryptionKey: encryptionKey,
		expiresAt:     expiresAt,
		file:          file,
	}, nil
}

func (sl *SessionLogger) LogEntry(entry SessionLogEntry) error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	if sl.file == nil {
		return fmt.Errorf("session logger not initialized")
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	encryptedData, err := EncryptData(jsonData, sl.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Use session-level mutex to ensure atomic writes across concurrent connections
	sessionMutex := getSessionMutex(sl.sessionID, sl.expiresAt)
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	// Write length-prefixed encrypted record (4 bytes length + encrypted data)
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(encryptedData)))

	if _, err := sl.file.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}

	if _, err := sl.file.Write(encryptedData); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	if err := sl.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	return nil
}

func (sl *SessionLogger) Close() error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	if sl.file == nil {
		return nil
	}

	err := sl.file.Close()
	sl.file = nil
	return err
}
