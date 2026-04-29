package session

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	// Storage backend values sent to and received from the Infisical API
	// These are distinct from the ResourceType* constants which identify protocol types
	storageBackendPostgres = "postgres"
	storageBackendAwsS3    = "aws-s3"

	pamRecordingAadVersion = "v1"

	pamRecordingIvBytes = 12

	pamRecordingMaxPlaintextBytes = 64 * 1024 * 1024

	// How long past .enc file expiry to wait before force-deleting orphaned chunks
	// Allows time for a reconnecting user to re-populate recording secrets
	orphanChunkGracePeriod = 5 * time.Minute

	s3PutTimeout = 2 * time.Minute
)

type ChunkUploader struct {
	httpClient         *resty.Client
	credentialsManager *CredentialsManager
	nextChunkIndex     map[string]int
	nextChunkIndexMu   sync.Mutex
}

func NewChunkUploader(httpClient *resty.Client, credentialsManager *CredentialsManager) *ChunkUploader {
	return &ChunkUploader{
		httpClient:         httpClient,
		credentialsManager: credentialsManager,
		nextChunkIndex:     make(map[string]int),
	}
}

func chunkQueueDir(sessionID string) string {
	return filepath.Join(GetSessionRecordingDir(), "chunks", sessionID)
}

func chunkIndexFile(sessionID string) string {
	return filepath.Join(GetSessionRecordingDir(), "chunks", sessionID+".chunkindex")
}

func chunkPendingFile(sessionID string, chunkIndex int) string {
	return filepath.Join(chunkQueueDir(sessionID), fmt.Sprintf("%06d.chunk", chunkIndex))
}

func (cu *ChunkUploader) loadNextChunkIndex(sessionID string) int {
	cu.nextChunkIndexMu.Lock()
	defer cu.nextChunkIndexMu.Unlock()
	if v, ok := cu.nextChunkIndex[sessionID]; ok {
		return v
	}
	data, err := os.ReadFile(chunkIndexFile(sessionID))
	if err == nil {
		if parsed, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil {
			cu.nextChunkIndex[sessionID] = parsed
			return parsed
		}
		log.Warn().Str("sessionId", sessionID).Msg("Corrupt chunkindex file, recovering from chunk dir")
	}
	idx := cu.scanMaxChunkIndex(sessionID)
	cu.nextChunkIndex[sessionID] = idx
	return idx
}

func (cu *ChunkUploader) scanMaxChunkIndex(sessionID string) int {
	dir := chunkQueueDir(sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	maxIdx := -1
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".chunk") {
			continue
		}
		numStr := strings.TrimSuffix(name, ".chunk")
		if n, parseErr := strconv.Atoi(numStr); parseErr == nil && n > maxIdx {
			maxIdx = n
		}
	}
	if maxIdx < 0 {
		return 0
	}
	return maxIdx + 1
}

// saveNextChunkIndex must only be called after the chunk file is durably on disk
func (cu *ChunkUploader) saveNextChunkIndex(sessionID string, idx int) {
	cu.nextChunkIndexMu.Lock()
	cu.nextChunkIndex[sessionID] = idx
	cu.nextChunkIndexMu.Unlock()

	dir := filepath.Dir(chunkIndexFile(sessionID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to create chunkindex dir")
		return
	}
	tmp := chunkIndexFile(sessionID) + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(idx)), 0o600); err != nil {
		log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to persist next chunk index")
		return
	}
	_ = os.Rename(tmp, chunkIndexFile(sessionID))
}

type pendingChunk struct {
	ChunkIndex     int    `json:"chunkIndex"`
	StartElapsedMs int64  `json:"startElapsedMs"`
	EndElapsedMs   int64  `json:"endElapsedMs"`
	IV             []byte `json:"iv"`
	Ciphertext     []byte `json:"ciphertext"`
	Sha256         []byte `json:"sha256"`
	StorageBackend string `json:"storageBackend"`
}

func writePendingChunk(sessionID string, pc *pendingChunk) error {
	dir := chunkQueueDir(sessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create chunk queue dir: %w", err)
	}
	tmp := chunkPendingFile(sessionID, pc.ChunkIndex) + ".tmp"
	body, err := json.Marshal(pc)
	if err != nil {
		return fmt.Errorf("marshal pending chunk: %w", err)
	}
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, chunkPendingFile(sessionID, pc.ChunkIndex))
}

func readPendingChunk(path string) (*pendingChunk, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pc pendingChunk
	if err := json.Unmarshal(body, &pc); err != nil {
		return nil, err
	}
	return &pc, nil
}

func deletePendingChunk(sessionID string, chunkIndex int) {
	_ = os.Remove(chunkPendingFile(sessionID, chunkIndex))
}

// SHA-256( "{projectId}|{sessionId}|{chunkIndex}|{storageBackend}|v1" )
func buildChunkAad(projectID, sessionID string, chunkIndex int, storageBackend string) []byte {
	h := sha256.New()
	io.WriteString(h, projectID)
	io.WriteString(h, "|")
	io.WriteString(h, sessionID)
	io.WriteString(h, "|")
	io.WriteString(h, strconv.Itoa(chunkIndex))
	io.WriteString(h, "|")
	io.WriteString(h, storageBackend)
	io.WriteString(h, "|")
	io.WriteString(h, pamRecordingAadVersion)
	return h.Sum(nil)
}

func encryptChunkBytes(plaintext []byte, sessionKey []byte, aad []byte) (ciphertext, iv []byte, err error) {
	if len(sessionKey) != 32 {
		return nil, nil, fmt.Errorf("expected 32-byte session key, got %d", len(sessionKey))
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, pamRecordingIvBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	iv = make([]byte, pamRecordingIvBytes)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("rand.Read: %w", err)
	}
	ciphertext = gcm.Seal(nil, iv, plaintext, aad)
	return ciphertext, iv, nil
}

func (cu *ChunkUploader) EncryptAndQueueChunk(
	sessionID string,
	plaintext []byte,
	startElapsedMs, endElapsedMs int64,
) (*pendingChunk, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	if len(plaintext) > pamRecordingMaxPlaintextBytes {
		return nil, fmt.Errorf(
			"plaintext too large for one chunk [bytes=%d, max=%d]",
			len(plaintext),
			pamRecordingMaxPlaintextBytes,
		)
	}

	secrets := cu.credentialsManager.GetRecordingSecrets(sessionID)
	if secrets == nil {
		return nil, fmt.Errorf("no recording secrets for session %s", sessionID)
	}

	chunkIndex := cu.loadNextChunkIndex(sessionID)
	aad := buildChunkAad(secrets.ProjectId, sessionID, chunkIndex, secrets.StorageBackend)

	ciphertext, iv, err := encryptChunkBytes(plaintext, secrets.SessionKey, aad)
	if err != nil {
		return nil, fmt.Errorf("encryptChunk: %w", err)
	}
	digest := sha256.Sum256(ciphertext)

	pc := &pendingChunk{
		ChunkIndex:     chunkIndex,
		StartElapsedMs: startElapsedMs,
		EndElapsedMs:   endElapsedMs,
		IV:             iv,
		Ciphertext:     ciphertext,
		Sha256:         digest[:],
		StorageBackend: secrets.StorageBackend,
	}
	if err := writePendingChunk(sessionID, pc); err != nil {
		return nil, fmt.Errorf("write pending chunk: %w", err)
	}

	cu.saveNextChunkIndex(sessionID, chunkIndex+1)

	log.Debug().
		Str("sessionId", sessionID).
		Int("chunkIndex", chunkIndex).
		Int("ciphertextBytes", len(ciphertext)).
		Str("storageBackend", secrets.StorageBackend).
		Msg("Queued chunk for upload")
	return pc, nil
}

func (cu *ChunkUploader) UploadChunk(sessionID string, pc *pendingChunk) error {
	secrets := cu.credentialsManager.GetRecordingSecrets(sessionID)
	if secrets == nil {
		return fmt.Errorf("no recording secrets cached for session %s", sessionID)
	}

	switch pc.StorageBackend {
	case storageBackendAwsS3:
		presigned, err := api.CallPAMSessionChunkPresignedPut(
			cu.httpClient,
			sessionID,
			secrets.UploadToken,
			api.ChunkPresignedPutRequest{
				ChunkIndex:      pc.ChunkIndex,
				CiphertextBytes: int64(len(pc.Ciphertext)),
			},
		)
		if err != nil {
			return fmt.Errorf("presigned PUT mint failed: %w", err)
		}
		if err := s3PutCiphertext(presigned.URL, pc.Ciphertext); err != nil {
			return fmt.Errorf("S3 PUT failed: %w", err)
		}
	case storageBackendPostgres:
		// no-op: ciphertext sent inline with the metadata POST below
	default:
		return fmt.Errorf("unsupported storage backend: %s", pc.StorageBackend)
	}

	metadataReq := api.ChunkMetadataRequest{
		ChunkIndex:       pc.ChunkIndex,
		StartElapsedMs:   pc.StartElapsedMs,
		EndElapsedMs:     pc.EndElapsedMs,
		CiphertextSha256: base64.StdEncoding.EncodeToString(pc.Sha256),
		CiphertextBytes:  int64(len(pc.Ciphertext)),
		IV:               base64.StdEncoding.EncodeToString(pc.IV),
	}
	if pc.StorageBackend == storageBackendPostgres {
		metadataReq.Ciphertext = base64.StdEncoding.EncodeToString(pc.Ciphertext)
	}

	if err := api.CallPAMSessionChunkMetadata(cu.httpClient, sessionID, secrets.UploadToken, metadataReq); err != nil {
		return fmt.Errorf("chunk metadata POST failed: %w", err)
	}

	deletePendingChunk(sessionID, pc.ChunkIndex)
	log.Debug().
		Str("sessionId", sessionID).
		Int("chunkIndex", pc.ChunkIndex).
		Msg("Uploaded chunk")
	return nil
}

func (cu *ChunkUploader) ReconcileSession(sessionID string) {
	dir := chunkQueueDir(sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Str("sessionId", sessionID).Msg("Failed to list pending chunks")
		}
		return
	}

	if cu.credentialsManager.GetRecordingSecrets(sessionID) == nil {
		// Sweep stale .tmp files left by a crash mid-writePendingChunk
		// Only done when secrets are absent (post-restart);
		// when secrets are present, .tmp files may belong to an in-flight writePendingChunk on another goroutine
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".tmp") {
				_ = os.Remove(filepath.Join(dir, entry.Name()))
			}
		}

		hasChunks := false
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".chunk") {
				hasChunks = true
				break
			}
		}
		if !hasChunks {
			return
		}

		// If the .enc source file still exists and hasn't expired past the grace period,
		// the user may reconnect and re-populate recording secrets. Leave chunks for retry
		fileInfo, findErr := FindSessionFileBySessionID(sessionID)
		if findErr == nil && time.Now().Before(fileInfo.ExpiresAt.Add(orphanChunkGracePeriod)) {
			log.Debug().Str("sessionId", sessionID).
				Msg("Pending chunks with no recording secrets but .enc file exists; waiting for session reconnect")
			return
		}

		if findErr == nil {
			log.Warn().Str("sessionId", sessionID).Time("expiresAt", fileInfo.ExpiresAt).
				Msg("Orphaned chunks with expired .enc file past grace period; removing")
		} else {
			log.Warn().Str("sessionId", sessionID).
				Msg("Orphaned chunks with no recording secrets and no source file; removing")
		}
		_ = os.RemoveAll(dir)
		_ = os.Remove(chunkIndexFile(sessionID))
		cu.nextChunkIndexMu.Lock()
		delete(cu.nextChunkIndex, sessionID)
		cu.nextChunkIndexMu.Unlock()
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".chunk") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		pc, err := readPendingChunk(path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("Failed to read pending chunk")
			continue
		}
		if err := cu.UploadChunk(sessionID, pc); err != nil {
			log.Debug().
				Err(err).
				Str("sessionId", sessionID).
				Int("chunkIndex", pc.ChunkIndex).
				Msg("Reconciliation upload failed; will retry next tick")
		}
	}
}

func (cu *ChunkUploader) ReconcileAllSessions() {
	root := filepath.Join(GetSessionRecordingDir(), "chunks")
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Msg("Failed to list chunk queue root")
		}
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cu.ReconcileSession(entry.Name())
	}
}

// CleanupSession removes the chunk queue dir and index file if no pending chunks remain
// Returns true if the session is fully cleaned up (no pending chunks)
func (cu *ChunkUploader) CleanupSession(sessionID string) bool {
	dir := chunkQueueDir(sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".chunk") {
			return false
		}
	}
	_ = os.RemoveAll(dir)
	_ = os.Remove(chunkIndexFile(sessionID))
	cu.nextChunkIndexMu.Lock()
	delete(cu.nextChunkIndex, sessionID)
	cu.nextChunkIndexMu.Unlock()
	return true
}

func s3PutCiphertext(presignedURL string, ciphertext []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), s3PutTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, presignedURL, bytes.NewReader(ciphertext))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.ContentLength = int64(len(ciphertext))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("PUT: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("S3 PUT returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
