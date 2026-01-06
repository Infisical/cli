package session

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

var ErrSessionFileNotFound = errors.New("session file not found")

// Resource type constants
const (
	ResourceTypePostgres   = "postgres"
	ResourceTypeMysql      = "mysql"
	ResourceTypeSSH        = "ssh"
	ResourceTypeKubernetes = "kubernetes"
)

type SessionFileInfo struct {
	SessionID    string
	ExpiresAt    time.Time
	Filename     string
	ResourceType string // ResourceTypeSSH, ResourceTypePostgres, ResourceTypeMysql (empty for legacy files)
}

type SessionUploader struct {
	httpClient         *resty.Client
	credentialsManager *CredentialsManager
	ticker             *time.Ticker
	stopChan           chan struct{}
	startOnce          sync.Once
}

func NewSessionUploader(httpClient *resty.Client, credentialsManager *CredentialsManager) *SessionUploader {
	return &SessionUploader{
		httpClient:         httpClient,
		credentialsManager: credentialsManager,
		stopChan:           make(chan struct{}),
	}
}

func ParseSessionFilename(filename string) (*SessionFileInfo, error) {
	// Try new format first: pam_session_{sessionID}_{resourceType}_expires_{timestamp}.enc
	// Build regex pattern using constants
	resourceTypePattern := fmt.Sprintf("(%s|%s|%s|%s)", ResourceTypeSSH, ResourceTypePostgres, ResourceTypeMysql, ResourceTypeKubernetes)
	newFormatRegex := regexp.MustCompile(fmt.Sprintf(`^pam_session_(.+)_%s_expires_(\d+)\.enc$`, resourceTypePattern))
	matches := newFormatRegex.FindStringSubmatch(filename)

	if len(matches) == 4 {
		sessionID := matches[1]
		resourceType := matches[2]
		timestampStr := matches[3]

		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp in filename %s: %w", filename, err)
		}

		return &SessionFileInfo{
			SessionID:    sessionID,
			ExpiresAt:    time.Unix(timestamp, 0),
			Filename:     filename,
			ResourceType: resourceType,
		}, nil
	}

	// Fall back to legacy format for backwards compatibility: pam_session_{sessionID}_expires_{timestamp}.enc
	legacyFormatRegex := regexp.MustCompile(`^pam_session_(.+)_expires_(\d+)\.enc$`)
	matches = legacyFormatRegex.FindStringSubmatch(filename)
	if len(matches) != 3 {
		return nil, fmt.Errorf("filename %s does not match expected format", filename)
	}

	sessionID := matches[1]
	timestampStr := matches[2]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp in filename %s: %w", filename, err)
	}

	return &SessionFileInfo{
		SessionID:    sessionID,
		ExpiresAt:    time.Unix(timestamp, 0),
		Filename:     filename,
		ResourceType: "", // Empty for legacy files (assume database format)
	}, nil
}

func ListSessionFiles() ([]*SessionFileInfo, error) {
	recordingDir := GetSessionRecordingDir()
	if err := os.MkdirAll(recordingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session recording directory: %w", err)
	}

	entries, err := os.ReadDir(recordingDir)
	if err != nil {
		if os.IsPermission(err) {
			log.Warn().Err(err).Str("recordingDir", recordingDir).Msg("Unable to access PAM session recording directory due to permissions - this can be ignored if PAM is not being used")
			return []*SessionFileInfo{}, nil
		}
		return nil, fmt.Errorf("failed to read session recording directory: %w", err)
	}

	var sessionFiles []*SessionFileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fileInfo, err := ParseSessionFilename(entry.Name())
		if err != nil {
			// Skip files that don't match our format
			continue
		}

		sessionFiles = append(sessionFiles, fileInfo)
	}

	return sessionFiles, nil
}

func GetExpiredSessionFiles() ([]*SessionFileInfo, error) {
	allFiles, err := ListSessionFiles()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var expiredFiles []*SessionFileInfo

	for _, file := range allFiles {
		if now.After(file.ExpiresAt) {
			expiredFiles = append(expiredFiles, file)
		}
	}

	return expiredFiles, nil
}

func readEncryptedEntries[T any](filename, encryptionKey string) ([]T, error) {
	recordingDir := GetSessionRecordingDir()
	fullPath := filepath.Join(recordingDir, filename)

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open session file: %w", err)
	}
	defer file.Close()

	var entries []T

	for {
		// Read length prefix (4 bytes)
		lengthBytes := make([]byte, 4)
		n, err := file.Read(lengthBytes)
		if err == io.EOF {
			break // End of file
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read length prefix: %w", err)
		}
		if n != 4 {
			return nil, fmt.Errorf("incomplete length prefix read")
		}

		length := binary.BigEndian.Uint32(lengthBytes)

		encryptedData := make([]byte, length)
		if n, err = io.ReadFull(file, encryptedData); err != nil {
			return nil, fmt.Errorf("failed to read encrypted data: %w", err)
		}
		if uint32(n) != length {
			return nil, fmt.Errorf("incomplete encrypted data read")
		}

		decryptedData, err := DecryptData(encryptedData, encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}

		var entry T
		if err := json.Unmarshal(decryptedData, &entry); err != nil {
			return nil, fmt.Errorf("failed to unmarshal entry: %w", err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func ReadEncryptedSessionLogByFilename(filename string, encryptionKey string) ([]SessionLogEntry, error) {
	return readEncryptedEntries[SessionLogEntry](filename, encryptionKey)
}

func ReadEncryptedTerminalEventsFromFile(filename string, encryptionKey string) ([]TerminalEvent, error) {
	return readEncryptedEntries[TerminalEvent](filename, encryptionKey)
}

func ReadEncryptedHttpEventsFromFile(filename string, encryptionKey string) ([]HttpEvent, error) {
	return readEncryptedEntries[HttpEvent](filename, encryptionKey)
}

func (su *SessionUploader) Start() {
	su.startOnce.Do(su.startUploadRoutine)
}

func (su *SessionUploader) startUploadRoutine() {
	log.Info().Msg("Starting PAM session uploader routine")

	su.ticker = time.NewTicker(5 * time.Minute)

	go func() {
		defer su.ticker.Stop()

		// call once immediately
		su.uploadExpiredSessionFiles()

		for {
			select {
			case <-su.ticker.C:
				su.uploadExpiredSessionFiles()
			case <-su.stopChan:
				return
			}
		}
	}()
}

func (su *SessionUploader) uploadExpiredSessionFiles() {
	expiredFiles, err := GetExpiredSessionFiles()
	if err != nil {
		log.Error().Err(err).Msg("Error getting expired session files")
		return
	}

	for _, fileInfo := range expiredFiles {
		log.Info().
			Str("sessionId", fileInfo.SessionID).
			Str("filename", fileInfo.Filename).
			Time("expiresAt", fileInfo.ExpiresAt).
			Msg("Processing expired session file")

		if err := su.CleanupPAMSession(fileInfo.SessionID, "orphaned_file"); err != nil {
			log.Error().Err(err).
				Str("sessionId", fileInfo.SessionID).
				Str("filename", fileInfo.Filename).
				Msg("Failed to cleanup expired PAM session")
			continue
		}

		log.Info().
			Str("sessionId", fileInfo.SessionID).
			Str("filename", fileInfo.Filename).
			Msg("Successfully processed expired session file")
	}
}

func (su *SessionUploader) uploadSessionFile(fileInfo *SessionFileInfo) error {
	encryptionKey, err := su.credentialsManager.GetPAMSessionEncryptionKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Use resource type to determine how to read the file
	if fileInfo.ResourceType == ResourceTypeSSH {
		// SSH session - read as terminal events
		terminalEvents, err := ReadEncryptedTerminalEventsFromFile(fileInfo.Filename, encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to read SSH session file: %w", err)
		}

		log.Debug().
			Str("sessionId", fileInfo.SessionID).
			Str("resourceType", fileInfo.ResourceType).
			Int("eventCount", len(terminalEvents)).
			Msg("Uploading terminal session events")

		var logs []api.UploadTerminalEvent
		for _, event := range terminalEvents {
			logs = append(logs, api.UploadTerminalEvent{
				Timestamp:   event.Timestamp,
				EventType:   string(event.EventType),
				Data:        event.Data,
				ElapsedTime: event.ElapsedTime,
			})
		}

		request := api.UploadPAMSessionLogsRequest{
			Logs: logs,
		}

		return api.CallUploadPamSessionLogs(su.httpClient, fileInfo.SessionID, request)
	}
	if fileInfo.ResourceType == ResourceTypeKubernetes {
		httpEvents, err := ReadEncryptedHttpEventsFromFile(fileInfo.Filename, encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to read SSH session file: %w", err)
		}

		log.Debug().
			Str("sessionId", fileInfo.SessionID).
			Str("resourceType", fileInfo.ResourceType).
			Int("eventCount", len(httpEvents)).
			Msg("Uploading terminal session events")

		var logs []api.UploadHttpEvent
		for _, event := range httpEvents {
			logs = append(logs, api.UploadHttpEvent{
				Timestamp: event.Timestamp,
				EventType: string(event.EventType),
				RequestId: event.RequestId,
				Method:    event.Method,
				Url:       event.URL,
				Status:    event.Status,
				Headers:   event.Headers,
				Body:      event.Body,
			})
		}

		request := api.UploadPAMSessionLogsRequest{
			Logs: logs,
		}

		return api.CallUploadPamSessionLogs(su.httpClient, fileInfo.SessionID, request)
	}

	// Database session (postgres, mysql, or legacy format) - read as request/response logs
	entries, err := ReadEncryptedSessionLogByFilename(fileInfo.Filename, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to read session file: %w", err)
	}

	resourceTypeMsg := fileInfo.ResourceType
	if resourceTypeMsg == "" {
		resourceTypeMsg = "legacy"
	}

	log.Debug().
		Str("sessionId", fileInfo.SessionID).
		Str("resourceType", resourceTypeMsg).
		Int("entryCount", len(entries)).
		Msg("Uploading database session logs")

	var logs []api.UploadSessionLogEntry
	for _, entry := range entries {
		logs = append(logs, api.UploadSessionLogEntry{
			Timestamp: entry.Timestamp,
			Input:     entry.Input,
			Output:    entry.Output,
		})
	}

	request := api.UploadPAMSessionLogsRequest{
		Logs: logs,
	}

	return api.CallUploadPamSessionLogs(su.httpClient, fileInfo.SessionID, request)
}

func FindSessionFileBySessionID(sessionID string) (*SessionFileInfo, error) {
	allFiles, err := ListSessionFiles()
	if err != nil {
		return nil, err
	}

	for _, file := range allFiles {
		if file.SessionID == sessionID {
			return file, nil
		}
	}

	return nil, ErrSessionFileNotFound
}

func (su *SessionUploader) UploadSessionLogsBySessionID(sessionID string) error {
	fileInfo, err := FindSessionFileBySessionID(sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionFileNotFound) {
			log.Debug().Str("sessionId", sessionID).Msg("Session file not found, skipping upload")
			return nil
		}
		return fmt.Errorf("failed to find session file: %w", err)
	}

	log.Info().Str("sessionId", sessionID).Str("filename", fileInfo.Filename).Msg("Uploading session logs for terminating session")

	if err := su.uploadSessionFile(fileInfo); err != nil {
		return fmt.Errorf("failed to upload session logs: %w", err)
	}

	// Delete the uploaded file
	recordingDir := GetSessionRecordingDir()
	fullPath := filepath.Join(recordingDir, fileInfo.Filename)
	if err := os.Remove(fullPath); err != nil {
		log.Warn().Err(err).Str("filename", fileInfo.Filename).Msg("Failed to delete uploaded session file")
		return fmt.Errorf("failed to delete uploaded session file: %w", err)
	}

	log.Info().Str("sessionId", sessionID).Str("filename", fileInfo.Filename).Msg("Successfully uploaded and deleted session file")
	return nil
}

// CleanupPAMSession handles the complete cleanup process for a PAM session
func (su *SessionUploader) CleanupPAMSession(sessionID string, reason string) error {
	log.Info().Str("sessionId", sessionID).Str("reason", reason).Msg("Starting PAM session cleanup")

	// Upload session logs
	if err := su.UploadSessionLogsBySessionID(sessionID); err != nil {
		log.Error().Err(err).Str("sessionId", sessionID).Msg("Failed to upload session logs")
	} else {
		log.Info().Str("sessionId", sessionID).Msg("Successfully uploaded session logs")
	}

	// Cleanup session resources
	CleanupSessionMutex(sessionID)
	su.credentialsManager.CleanupSessionCredentials(sessionID)

	if err := api.CallPAMSessionTermination(su.httpClient, sessionID); err != nil {
		log.Error().Err(err).Str("sessionId", sessionID).Msg("Failed to notify session termination via API")
		return err
	} else {
		log.Info().Str("sessionId", sessionID).Msg("Session termination processed successfully")
	}

	return nil
}

func (su *SessionUploader) Stop() {
	close(su.stopChan)
}
