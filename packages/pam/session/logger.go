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

// TerminalEventType represents the type of terminal event
type TerminalEventType string

const (
	TerminalEventInput  TerminalEventType = "input"  // Data from user to server
	TerminalEventOutput TerminalEventType = "output" // Data from server to user
)

// TerminalEvent represents a single event in a terminal session
type TerminalEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   TerminalEventType `json:"eventType"`
	Data        []byte            `json:"data"`        // Raw terminal data
	ElapsedTime float64           `json:"elapsedTime"` // Seconds since session start (for replay)
}

type SessionLogger interface {
	LogEntry(entry SessionLogEntry) error
	LogTerminalEvent(event TerminalEvent) error
	Close() error
}

type EncryptedSessionLogger struct {
	sessionID     string
	encryptionKey string
	expiresAt     time.Time
	file          *os.File
	mutex         sync.Mutex
	sessionStart  time.Time // Track session start time for elapsed time calculation
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

func NewSessionLogger(sessionID string, encryptionKey string, expiresAt time.Time, resourceType string) (*EncryptedSessionLogger, error) {
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

	// Use new filename format with resource type if provided
	var filename string
	if resourceType != "" {
		filename = fmt.Sprintf("pam_session_%s_%s_expires_%d.enc", sessionID, resourceType, expiresAt.Unix())
	} else {
		// Legacy format for backwards compatibility
		filename = fmt.Sprintf("pam_session_%s_expires_%d.enc", sessionID, expiresAt.Unix())
	}
	fullPath := filepath.Join(recordingDir, filename)

	// Open file in append mode to support multiple connections per session
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open session file: %w", err)
	}

	return &EncryptedSessionLogger{
		sessionID:     sessionID,
		encryptionKey: encryptionKey,
		expiresAt:     expiresAt,
		file:          file,
		sessionStart:  time.Now(),
	}, nil
}

func (sl *EncryptedSessionLogger) LogEntry(entry SessionLogEntry) error {
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

func (sl *EncryptedSessionLogger) LogTerminalEvent(event TerminalEvent) error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	if sl.file == nil {
		return fmt.Errorf("session logger not initialized")
	}

	// Calculate elapsed time if not already set
	if event.ElapsedTime == 0 {
		event.ElapsedTime = time.Since(sl.sessionStart).Seconds()
	}

	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal terminal event: %w", err)
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

	// For high-frequency events like terminal I/O, we might want to buffer
	// But for now, sync to ensure durability
	if err := sl.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	return nil
}

func (sl *EncryptedSessionLogger) Close() error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	if sl.file == nil {
		return nil
	}

	err := sl.file.Close()
	sl.file = nil
	return err
}
