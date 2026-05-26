package session

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

// SessionEventType represents the type of session event
type SessionEventType string

const (
	SessionEventInput  SessionEventType = "input"  // Data from user to server
	SessionEventOutput SessionEventType = "output" // Data from server to user
	SessionEventRDP    SessionEventType = "rdp"    // RDP tap event (see SessionChannelRDP)
)

// SessionChannelType represents the type of SSH channel
type SessionChannelType string

const (
	SessionChannelShell SessionChannelType = "terminal" // Interactive shell session
	SessionChannelExec  SessionChannelType = "exec"     // Single command execution
	SessionChannelSFTP  SessionChannelType = "sftp"     // SFTP file transfer
	SessionChannelRDP   SessionChannelType = "rdp"      // RDP frame/input tap; Data carries an RDP-specific JSON envelope
)

// SessionEvent represents a single event in a recorded session (SSH or RDP).
type SessionEvent struct {
	Timestamp   time.Time            `json:"timestamp"`
	EventType   SessionEventType    `json:"eventType"`
	ChannelType SessionChannelType  `json:"channelType,omitempty"` // Channel kind (SSH shell/exec/sftp or RDP)
	Data        []byte               `json:"data"`                  // SSH: raw terminal bytes; RDP: JSON envelope (base64-marshaled)
	ElapsedTime float64              `json:"elapsedTime"`           // Seconds since session start (for replay)
}

type HttpEventType string

type HttpEvent struct {
	Timestamp time.Time `json:"timestamp"`
	// TODO: ideally this should be different polymorphic structs determined by the event type,
	// 		 just not sure what's the best way to do in go lang
	EventType HttpEventType `json:"eventType"`
	RequestId string        `json:"requestId"`
	Headers   http.Header   `json:"headers"`
	Method    string        `json:"method,omitempty"`
	URL       string        `json:"url,omitempty"`
	Status    string        `json:"status,omitempty"`
	Body      []byte        `json:"body,omitempty"`
}

const (
	HttpEventRequest  HttpEventType = "request"
	HttpEventResponse HttpEventType = "response"
)

type SessionLogger interface {
	LogEntry(entry SessionLogEntry) error
	LogSessionEvent(event SessionEvent) error
	LogHttpEvent(event HttpEvent) error
	Close() error
}

type EncryptedSessionLogger struct {
	sessionID       string
	encryptionKey   string
	expiresAt       time.Time
	file            *os.File
	mutex           sync.Mutex
	sessionStart    time.Time          // Track session start time for elapsed time calculation
	maskingPatterns []*regexp.Regexp   // Patterns for masking sensitive data in session logs
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

func NewSessionLogger(sessionID string, encryptionKey string, expiresAt time.Time, resourceType string, maskingPatterns []*regexp.Regexp) (*EncryptedSessionLogger, error) {
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
		sessionID:       sessionID,
		encryptionKey:   encryptionKey,
		expiresAt:       expiresAt,
		file:            file,
		sessionStart:    time.Now(),
		maskingPatterns: maskingPatterns,
	}, nil
}

func (sl *EncryptedSessionLogger) writeEvent(productEventData func() ([]byte, error)) error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	if sl.file == nil {
		return fmt.Errorf("session logger not initialized")
	}

	jsonData, err := productEventData()
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
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

// applyMasking replaces regex matches in byte data with [MASKED]
func (sl *EncryptedSessionLogger) applyMasking(data []byte) []byte {
	if len(sl.maskingPatterns) == 0 || len(data) == 0 {
		return data
	}
	result := data
	for _, pattern := range sl.maskingPatterns {
		result = pattern.ReplaceAll(result, []byte("[MASKED]"))
	}
	return result
}

// applyMaskingString replaces regex matches in string data with [MASKED]
func (sl *EncryptedSessionLogger) applyMaskingString(s string) string {
	if len(sl.maskingPatterns) == 0 || s == "" {
		return s
	}
	result := s
	for _, pattern := range sl.maskingPatterns {
		result = pattern.ReplaceAllString(result, "[MASKED]")
	}
	return result
}

func (sl *EncryptedSessionLogger) LogEntry(entry SessionLogEntry) error {
	return sl.writeEvent(func() ([]byte, error) {
		entry.Input = sl.applyMaskingString(entry.Input)
		entry.Output = sl.applyMaskingString(entry.Output)
		return json.Marshal(entry)
	})
}

func (sl *EncryptedSessionLogger) LogSessionEvent(event SessionEvent) error {
	return sl.writeEvent(func() ([]byte, error) {
		if event.ElapsedTime == 0 {
			event.ElapsedTime = time.Since(sl.sessionStart).Seconds()
		}
		// RDP carries a structured JSON envelope (with base64-encoded PDU
		// bytes, scancodes, etc.) in Data, not free-form terminal text.
		// Masking patterns are SSH-shaped regexes; running them over the
		// envelope would corrupt valid recordings whenever a pattern
		// happened to match a substring of the JSON or base64.
		if event.ChannelType != SessionChannelRDP {
			event.Data = sl.applyMasking(event.Data)
		}
		return json.Marshal(event)
	})
}

func (sl *EncryptedSessionLogger) LogHttpEvent(event HttpEvent) error {
	return sl.writeEvent(func() ([]byte, error) {
		event.Body = sl.applyMasking(event.Body)
		return json.Marshal(event)
	})
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
