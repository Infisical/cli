package session

import (
	"encoding/binary"
	"encoding/json"
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

type SessionFileInfo struct {
	SessionID string
	ExpiresAt time.Time
	Filename  string
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
	regex := regexp.MustCompile(`^pam_session_(.+)_expires_(\d+)\.enc$`)
	matches := regex.FindStringSubmatch(filename)
	if len(matches) != 3 {
		return nil, fmt.Errorf("filename %s does not match expected format: pam_session_{sessionID}_expires_{timestamp}.enc", filename)
	}

	sessionID := matches[1]
	timestampStr := matches[2]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp in filename %s: %w", filename, err)
	}

	return &SessionFileInfo{
		SessionID: sessionID,
		ExpiresAt: time.Unix(timestamp, 0),
		Filename:  filename,
	}, nil
}

func ListSessionFiles() ([]*SessionFileInfo, error) {
	recordingDir := GetSessionRecordingDir()

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

func ReadEncryptedSessionLogByFilename(filename string, encryptionKey string) ([]SessionLogEntry, error) {
	recordingDir := GetSessionRecordingDir()
	fullPath := filepath.Join(recordingDir, filename)

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open session file: %w", err)
	}
	defer file.Close()

	var entries []SessionLogEntry

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
		n, err = io.ReadFull(file, encryptedData)
		if err != nil {
			return nil, fmt.Errorf("failed to read encrypted data: %w", err)
		}
		if uint32(n) != length {
			return nil, fmt.Errorf("incomplete encrypted data read")
		}

		decryptedData, err := DecryptData(encryptedData, encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt session data: %w", err)
		}

		var entry SessionLogEntry
		if err := json.Unmarshal(decryptedData, &entry); err != nil {
			return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
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

	entries, err := ReadEncryptedSessionLogByFilename(fileInfo.Filename, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to read session file: %w", err)
	}

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

	return nil, fmt.Errorf("session file not found for session ID: %s", sessionID)
}

func (su *SessionUploader) UploadSessionLogsBySessionID(sessionID string) error {
	fileInfo, err := FindSessionFileBySessionID(sessionID)
	if err != nil {
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
