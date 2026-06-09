package session

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	ResourceTypeMssql      = "mssql"
	ResourceTypeRedis      = "redis"
	ResourceTypeSSH        = "ssh"
	ResourceTypeKubernetes = "kubernetes"
	ResourceTypeMongodb    = "mongodb"
	ResourceTypeOracledb = "oracledb"
	ResourceTypeWindows  = "windows"
)

type SessionFileInfo struct {
	SessionID    string
	ExpiresAt    time.Time
	Filename     string
	ResourceType string // ResourceTypeSSH, ResourceTypePostgres, ResourceTypeMysql (empty for legacy files)
}

type sessionUploadState struct {
	fileOffset       int64
	filename         string // base filename (not full path) of the session recording
	legacyMode       bool   // true if the batch upload endpoint returned 404 (platform too old); fall back to bulk upload at session end
	startedAt        time.Time
	lastEndElapsedMs int64
	// Advanced per-event by streaming writers so GetPriorElapsedNs sees a fresh
	// anchor between flush ticks (rapid RDP reconnects within the 10s window).
	lastEmittedElapsedNs atomic.Uint64
	mu                   sync.Mutex
}

type SessionUploader struct {
	httpClient         *resty.Client
	credentialsManager *CredentialsManager
	chunkUploader      *ChunkUploader
	ticker             *time.Ticker
	stopChan           chan struct{}
	startOnce          sync.Once

	activeSessions   map[string]*sessionUploadState
	activeSessionsMu sync.RWMutex
}

func NewSessionUploader(httpClient *resty.Client, credentialsManager *CredentialsManager) *SessionUploader {
	return &SessionUploader{
		httpClient:         httpClient,
		credentialsManager: credentialsManager,
		chunkUploader:      NewChunkUploader(httpClient, credentialsManager),
		stopChan:           make(chan struct{}),
		activeSessions:     make(map[string]*sessionUploadState),
	}
}

func ParseSessionFilename(filename string) (*SessionFileInfo, error) {
	// Try new format first: pam_session_{sessionID}_{resourceType}_expires_{timestamp}.enc
	// Build regex pattern using constants
	resourceTypePattern := fmt.Sprintf("(%s|%s|%s|%s|%s|%s|%s|%s|%s)", ResourceTypeSSH, ResourceTypePostgres, ResourceTypeRedis, ResourceTypeMysql, ResourceTypeMssql, ResourceTypeKubernetes, ResourceTypeMongodb, ResourceTypeOracledb, ResourceTypeWindows)
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
			// Skip files that don't match our format (including .offset sidecars)
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

func ReadEncryptedSessionEventsFromFile(filename string, encryptionKey string) ([]SessionEvent, error) {
	return readEncryptedEntries[SessionEvent](filename, encryptionKey)
}

func ReadEncryptedHttpEventsFromFile(filename string, encryptionKey string) ([]HttpEvent, error) {
	return readEncryptedEntries[HttpEvent](filename, encryptionKey)
}

// offsetFilePath returns the path to the persisted offset file for a given recording filename.
func offsetFilePath(filename string) string {
	return filepath.Join(GetSessionRecordingDir(), strings.TrimSuffix(filename, ".enc")+".offset")
}

// readPersistedOffset reads the persisted file offset and last elapsed-ms marker
// Format: line 1 = offset, line 2 = lastEndElapsedMs (optional, 0 if missing for backward compat)
func readPersistedOffset(filename string) (offset int64, lastEndElapsedMs int64, ok bool) {
	data, err := os.ReadFile(offsetFilePath(filename))
	if err != nil {
		return 0, 0, false
	}
	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	offset, err = strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	if err != nil {
		return 0, 0, false
	}
	if len(lines) > 1 {
		lastEndElapsedMs, _ = strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	}
	return offset, lastEndElapsedMs, true
}

func writePersistedOffset(filename string, offset int64, lastEndElapsedMs int64) error {
	path := offsetFilePath(filename)
	tmpPath := path + ".tmp"
	content := fmt.Sprintf("%d\n%d", offset, lastEndElapsedMs)
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// deletePersistedOffset removes the offset file for a session.
func deletePersistedOffset(filename string) {
	_ = os.Remove(offsetFilePath(filename))
}

// Returns (payload JSON array, new offset, last entry's elapsedMs, hasMore, err).
// lastEntryElapsedMs is 0 if entries lack the field. maxPayloadBytes>0
// caps the JSON array size; hasMore is true only when the cap was hit with at
// least one more record already pending (a genuine backlog). The caller drains
// while hasMore is true, then stops at the live write edge instead of spinning
// one chunk per event as the recorder appends.
func readFromOffset(filename, encryptionKey string, offset int64, maxPayloadBytes int) ([]byte, int64, int64, bool, error) {
	recordingDir := GetSessionRecordingDir()
	fullPath := filepath.Join(recordingDir, filename)

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, offset, 0, false, fmt.Errorf("failed to open session file: %w", err)
	}
	defer file.Close()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, 0, false, fmt.Errorf("failed to seek to offset %d: %w", offset, err)
	}

	var entries []json.RawMessage
	newOffset := offset
	runningSize := 2 // account for JSON array brackets []
	var lastEntryElapsedMs int64
	hasMore := false

	for {
		lengthBytes := make([]byte, 4)
		if _, err := io.ReadFull(file, lengthBytes); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break // No more complete records
			}
			return nil, newOffset, 0, false, fmt.Errorf("failed to read length prefix: %w", err)
		}

		length := binary.BigEndian.Uint32(lengthBytes)
		encryptedData := make([]byte, length)
		if _, err := io.ReadFull(file, encryptedData); err != nil {
			break // Partial record at EOF, stop here and retry next tick
		}

		decryptedData, err := DecryptData(encryptedData, encryptionKey)
		if err != nil {
			return nil, newOffset, 0, false, fmt.Errorf("failed to decrypt record at offset %d: %w", newOffset, err)
		}

		entrySize := len(decryptedData)
		if len(entries) > 0 {
			entrySize++ // comma separator
		}
		if maxPayloadBytes > 0 && len(entries) > 0 && runningSize+entrySize > maxPayloadBytes {
			hasMore = true // filled a chunk with a record still pending; caller keeps draining
			break
		}

		// Probe the entry's elapsedTime field. Absent on HTTP/Kubernetes events.
		var probe struct {
			ElapsedTime float64 `json:"elapsedTime"`
		}
		if jsonErr := json.Unmarshal(decryptedData, &probe); jsonErr == nil && probe.ElapsedTime > 0 {
			lastEntryElapsedMs = int64(probe.ElapsedTime * 1000)
		}

		entries = append(entries, json.RawMessage(decryptedData))
		newOffset += int64(4 + length)
		runningSize += entrySize
	}

	if len(entries) == 0 {
		return nil, newOffset, 0, false, nil
	}

	payload, err := json.Marshal(entries)
	if err != nil {
		return nil, newOffset, 0, false, fmt.Errorf("failed to marshal event batch: %w", err)
	}

	return payload, newOffset, lastEntryElapsedMs, hasMore, nil
}

// GetPriorElapsedNs returns the last recorded elapsed time for this session
// in nanoseconds. On reconnects this is added to the bridge's elapsed_ns so
// timestamps stay monotonic across bridge restarts.
func (su *SessionUploader) GetPriorElapsedNs(sessionID string) uint64 {
	su.activeSessionsMu.RLock()
	defer su.activeSessionsMu.RUnlock()
	state, ok := su.activeSessions[sessionID]
	if !ok {
		return 0
	}
	emitted := state.lastEmittedElapsedNs.Load()
	flushed := uint64(state.lastEndElapsedMs) * 1_000_000
	if emitted > flushed {
		return emitted
	}
	return flushed
}

// Monotonically advances the per-session GetPriorElapsedNs anchor; stale values are ignored.
func (su *SessionUploader) RecordEmittedElapsedNs(sessionID string, elapsedNs uint64) {
	su.activeSessionsMu.RLock()
	state, ok := su.activeSessions[sessionID]
	su.activeSessionsMu.RUnlock()
	if !ok {
		return
	}
	for {
		cur := state.lastEmittedElapsedNs.Load()
		if elapsedNs <= cur {
			return
		}
		if state.lastEmittedElapsedNs.CompareAndSwap(cur, elapsedNs) {
			return
		}
	}
}

// RegisterSession registers a session for incremental batch uploads, resuming from
// any previously persisted offset if present.
func (su *SessionUploader) RegisterSession(sessionID string) {
	fileInfo, err := FindSessionFileBySessionID(sessionID)
	if err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("[RegisterSession] session file not found, will retry on first flush")
		return
	}

	var startOffset int64
	var lastEndElapsedMs int64
	if offset, elapsed, ok := readPersistedOffset(fileInfo.Filename); ok {
		startOffset = offset
		lastEndElapsedMs = elapsed
		log.Info().Str("sessionId", sessionID).Int64("resumeOffset", startOffset).Int64("lastEndElapsedMs", lastEndElapsedMs).
			Msg("Resuming incremental upload from persisted offset")
	}

	su.activeSessionsMu.Lock()
	// Preserve the original anchor across RDP reconnects within the same PAM
	// session: HandlePAMProxy calls RegisterSession on every gateway connection,
	// and overwriting the entry would reset startedAt to ~now, making elapsedNs
	// rewind on reconnect. The persisted .offset only catches up after a flush,
	// so it can't be the source of truth here.
	if _, exists := su.activeSessions[sessionID]; !exists {
		state := &sessionUploadState{
			fileOffset:       startOffset,
			filename:         fileInfo.Filename,
			startedAt:        time.Now().Add(-time.Duration(lastEndElapsedMs) * time.Millisecond),
			lastEndElapsedMs: lastEndElapsedMs,
		}
		state.lastEmittedElapsedNs.Store(uint64(lastEndElapsedMs) * 1_000_000)
		su.activeSessions[sessionID] = state
	}
	su.activeSessionsMu.Unlock()

	log.Debug().Str("sessionId", sessionID).Msg("Registered session for incremental batch upload")
}

// UnregisterSession removes a session from incremental tracking
func (su *SessionUploader) UnregisterSession(sessionID string) {
	su.activeSessionsMu.Lock()
	delete(su.activeSessions, sessionID)
	su.activeSessionsMu.Unlock()

	log.Debug().Str("sessionId", sessionID).Msg("Unregistered session from incremental batch upload")
}

func (su *SessionUploader) Start() {
	su.startOnce.Do(su.startUploadRoutine)
}

func (su *SessionUploader) startUploadRoutine() {
	log.Info().Msg("Starting PAM session uploader routine")

	su.ticker = time.NewTicker(5 * time.Minute)
	flushTicker := time.NewTicker(10 * time.Second)

	go func() {
		defer su.ticker.Stop()
		defer flushTicker.Stop()

		// On startup, drive final cleanup for any non-expired session files left on disk
		// (sessions that were active when the gateway last shut down or crashed).
		su.resumeInProgressSessions()

		// Process any orphaned expired files from previous runs immediately.
		su.uploadExpiredSessionFiles()
		su.chunkUploader.ReconcileAllSessions()

		for {
			select {
			case <-su.ticker.C:
				su.uploadExpiredSessionFiles()
				su.chunkUploader.ReconcileAllSessions()
			case <-flushTicker.C:
				su.flushActiveSessions()
			case <-su.stopChan:
				return
			}
		}
	}()
}

// Re-registers non-expired recording files at startup so the flush ticker
// can drain them. Expired files are handled by uploadExpiredSessionFiles.
func (su *SessionUploader) resumeInProgressSessions() {
	allFiles, err := ListSessionFiles()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list session files for resume on startup")
		return
	}

	now := time.Now()
	for _, fileInfo := range allFiles {
		if now.After(fileInfo.ExpiresAt) {
			continue
		}
		log.Info().Str("sessionId", fileInfo.SessionID).Str("filename", fileInfo.Filename).Msg("Resuming session upload after restart")
		su.RegisterSession(fileInfo.SessionID)

		su.credentialsManager.LoadRecordingSecretsFromDisk(fileInfo.SessionID)

		if _, err := su.credentialsManager.GetPAMSessionCredentials(fileInfo.SessionID, fileInfo.ExpiresAt); err != nil {
			log.Warn().Err(err).Str("sessionId", fileInfo.SessionID).
				Msg("Failed to re-fetch credentials on resume; logging and chunk creation will resume when client reconnects")
		}
	}
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

// flushActiveSessions uploads new events for all currently active sessions.
func (su *SessionUploader) flushActiveSessions() {
	encryptionKey, err := su.credentialsManager.GetPAMSessionEncryptionKey()
	if err != nil {
		log.Error().Err(err).Msg("[flushActiveSessions] failed to get encryption key")
		return
	}

	su.activeSessionsMu.RLock()
	sessionIDs := make([]string, 0, len(su.activeSessions))
	for id := range su.activeSessions {
		sessionIDs = append(sessionIDs, id)
	}
	su.activeSessionsMu.RUnlock()

	for _, sessionID := range sessionIDs {
		_ = su.flushSession(sessionID, encryptionKey) // errors already logged inside flushSession; ticker will retry next cycle
	}
}

// Uploads new events as a batch and advances the offset on success.
func (su *SessionUploader) flushSession(sessionID, encryptionKey string) error {
	su.activeSessionsMu.RLock()
	state, ok := su.activeSessions[sessionID]
	su.activeSessionsMu.RUnlock()
	if !ok {
		return nil
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.legacyMode {
		return nil // Platform does not support batch uploads; bulk upload will happen at session end
	}

	if secrets := su.credentialsManager.GetRecordingSecrets(sessionID); secrets != nil && len(secrets.SessionKey) == 32 {
		maxChunkBytes := pamRecordingMaxPlaintextBytes
		if secrets.StorageBackend == storageBackendPostgres {
			maxChunkBytes = pamPostgresMaxPlaintextBytes
		}
		startElapsedMs := state.lastEndElapsedMs
		currentOffset := state.fileOffset

		for {
			payload, newOffset, lastEntryElapsedMs, hasMore, err := readFromOffset(state.filename, encryptionKey, currentOffset, maxChunkBytes)
			if err != nil {
				log.Error().Err(err).Str("sessionId", sessionID).Msg("Failed to read session events for chunk upload")
				break
			}
			if len(payload) == 0 {
				break
			}

			// Wallclock fallback only when the chunk carried no elapsedTime at all
			// (HTTP/Kubernetes); otherwise it includes reconnect idle gaps.
			endElapsedMs := lastEntryElapsedMs
			if lastEntryElapsedMs == 0 {
				endElapsedMs = time.Since(state.startedAt).Milliseconds()
			} else if endElapsedMs < startElapsedMs {
				endElapsedMs = startElapsedMs
			}

			pc, encErr := su.chunkUploader.EncryptAndQueueChunk(sessionID, payload, startElapsedMs, endElapsedMs)
			if encErr != nil {
				log.Error().Err(encErr).Str("sessionId", sessionID).Msg("Failed to encrypt chunk; will retry on next tick")
				break
			}
			if upErr := su.chunkUploader.UploadChunk(sessionID, pc); upErr != nil {
				log.Error().Err(upErr).Str("sessionId", sessionID).Int("chunkIndex", pc.ChunkIndex).
					Msg("Chunk upload failed; will retry via reconciliation tick")
			}

			currentOffset = newOffset
			startElapsedMs = endElapsedMs

			state.lastEndElapsedMs = endElapsedMs
			state.fileOffset = currentOffset
			if err := writePersistedOffset(state.filename, currentOffset, endElapsedMs); err != nil {
				log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to persist offset after chunk flush")
			}

			// Only keep looping while there's a full chunk's worth of backlog. Once caught up
			// to the live write edge, stop and let the next flush tick batch what arrives, rather
			// than spinning one tiny chunk per event as the recorder appends.
			if !hasMore {
				break
			}
		}
		return nil
	}

	payload, newOffset, _, _, err := readFromOffset(state.filename, encryptionKey, state.fileOffset, 0)
	if err != nil {
		log.Error().Err(err).Str("sessionId", sessionID).Msg("Failed to read session events for batch upload")
		return err
	}
	if len(payload) == 0 {
		return nil // No new events since last flush
	}

	if err := api.CallUploadPamSessionEventBatch(su.httpClient, sessionID, state.fileOffset, payload); err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			// Platform does not support the batch upload endpoint yet; fall back to bulk upload at session end
			log.Warn().Str("sessionId", sessionID).Msg("Batch upload endpoint not supported by platform, falling back to legacy bulk upload")
			state.legacyMode = true
			return nil
		}
		log.Error().Err(err).Str("sessionId", sessionID).Int64("startOffset", state.fileOffset).Msg("Failed to upload session event batch, will retry next tick")
		return err // Do not advance offset on failure so the batch is retried
	}

	state.fileOffset = newOffset
	if err := writePersistedOffset(state.filename, newOffset, state.lastEndElapsedMs); err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to persist offset after flush")
	}

	log.Debug().Str("sessionId", sessionID).Int64("newOffset", newOffset).Msg("Flushed session event batch")
	return nil
}

func (su *SessionUploader) uploadSessionFile(fileInfo *SessionFileInfo) error {
	encryptionKey, err := su.credentialsManager.GetPAMSessionEncryptionKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	// SSH and Windows both write SessionEvent records (SSH uses input/output/
	// resize/error; Windows uses ChannelType=rdp). Bulk-uploading either via
	// the Database fallback would silently zero-fill input/output, dropping
	// the entire recording.
	if fileInfo.ResourceType == ResourceTypeSSH || fileInfo.ResourceType == ResourceTypeWindows {
		sessionEvents, err := ReadEncryptedSessionEventsFromFile(fileInfo.Filename, encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to read session event file: %w", err)
		}

		log.Debug().
			Str("sessionId", fileInfo.SessionID).
			Str("resourceType", fileInfo.ResourceType).
			Int("eventCount", len(sessionEvents)).
			Msg("Uploading session events")

		var logs []api.UploadSessionEvent
		for _, event := range sessionEvents {
			logs = append(logs, api.UploadSessionEvent{
				Timestamp:   event.Timestamp,
				EventType:   string(event.EventType),
				ChannelType: string(event.ChannelType),
				Data:        event.Data,
				ElapsedTime: event.ElapsedTime,
			})
		}

		return api.CallUploadPamSessionLogs(su.httpClient, fileInfo.SessionID, api.UploadPAMSessionLogsRequest{Logs: logs})
	}

	if fileInfo.ResourceType == ResourceTypeKubernetes {
		httpEvents, err := ReadEncryptedHttpEventsFromFile(fileInfo.Filename, encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to read Kubernetes session file: %w", err)
		}

		log.Debug().
			Str("sessionId", fileInfo.SessionID).
			Str("resourceType", fileInfo.ResourceType).
			Int("eventCount", len(httpEvents)).
			Msg("Uploading Kubernetes session events")

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

		return api.CallUploadPamSessionLogs(su.httpClient, fileInfo.SessionID, api.UploadPAMSessionLogsRequest{Logs: logs})
	}

	// Database session (postgres, mysql, mssql, redis, or legacy format)
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

	return api.CallUploadPamSessionLogs(su.httpClient, fileInfo.SessionID, api.UploadPAMSessionLogsRequest{Logs: logs})
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

// CleanupPAMSession performs a final batch upload, unregisters the session,
// deletes the local recording file, and notifies the server that the session has ended.
func (su *SessionUploader) CleanupPAMSession(sessionID string, reason string) error {
	log.Info().Str("sessionId", sessionID).Str("reason", reason).Msg("Starting PAM session cleanup")

	// Ensure the session is registered so the final flush can read from the correct offset.
	// This handles both active sessions (already registered) and orphaned files from previous runs.
	su.activeSessionsMu.RLock()
	_, isRegistered := su.activeSessions[sessionID]
	su.activeSessionsMu.RUnlock()
	if !isRegistered {
		su.RegisterSession(sessionID)
	}

	// On any failure here, return early so uploadExpiredSessionFiles can retry
	// past ExpiresAt; deleting the file on failure would lose events.
	encryptionKey, err := su.credentialsManager.GetPAMSessionEncryptionKey()
	if err != nil {
		log.Error().Err(err).Str("sessionId", sessionID).Msg("Could not get encryption key for final flush, keeping recording file for retry")
		return err
	}
	if flushErr := su.flushSession(sessionID, encryptionKey); flushErr != nil {
		log.Error().Err(flushErr).Str("sessionId", sessionID).Msg("Final batch flush failed at session end, keeping recording file for retry")
		return flushErr
	}

	// Legacy fallback: single bulk upload of the whole file.
	su.activeSessionsMu.RLock()
	state, stateExists := su.activeSessions[sessionID]
	su.activeSessionsMu.RUnlock()
	if stateExists {
		state.mu.Lock()
		useLegacy := state.legacyMode
		state.mu.Unlock()
		if useLegacy {
			fileInfo, err := FindSessionFileBySessionID(sessionID)
			if err != nil {
				log.Warn().Err(err).Str("sessionId", sessionID).Msg("Session file not found for legacy bulk upload")
			} else if uploadErr := su.uploadSessionFile(fileInfo); uploadErr != nil {
				log.Error().Err(uploadErr).Str("sessionId", sessionID).Str("filename", fileInfo.Filename).Msg("Legacy bulk upload failed at session end, keeping recording file for retry")
				return uploadErr
			}
		}
	}

	su.UnregisterSession(sessionID)

	su.chunkUploader.ReconcileSession(sessionID)
	chunksCleared := su.chunkUploader.CleanupSession(sessionID)

	if chunksCleared {
		fileInfo, findErr := FindSessionFileBySessionID(sessionID)
		if findErr == nil {
			deletePersistedOffset(fileInfo.Filename)
			recordingDir := GetSessionRecordingDir()
			fullPath := filepath.Join(recordingDir, fileInfo.Filename)
			if removeErr := os.Remove(fullPath); removeErr != nil && !os.IsNotExist(removeErr) {
				log.Warn().Err(removeErr).Str("filename", fileInfo.Filename).Msg("Failed to delete session recording file")
			} else {
				log.Info().Str("sessionId", sessionID).Str("filename", fileInfo.Filename).Msg("Deleted local session recording file")
			}
		}
		su.credentialsManager.CleanupSessionCredentials(sessionID)
	} else {
		log.Warn().Str("sessionId", sessionID).
			Msg("Pending chunks remain after reconciliation; recording file and secrets preserved for retry")
	}

	CleanupSessionMutex(sessionID)

	if err := api.CallPAMSessionTermination(su.httpClient, sessionID); err != nil {
		log.Error().Err(err).Str("sessionId", sessionID).Msg("Failed to notify session termination via API")
		return err
	}
	log.Info().Str("sessionId", sessionID).Msg("Session termination processed successfully")

	return nil
}

func (su *SessionUploader) Stop() {
	close(su.stopChan)
}
