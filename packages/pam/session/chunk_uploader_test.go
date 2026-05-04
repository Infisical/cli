package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	SetSessionRecordingPath(dir)
	t.Cleanup(func() { SetSessionRecordingPath("") })
}

func newTestCredentialsManager(t *testing.T) *CredentialsManager {
	t.Helper()
	return NewCredentialsManager(nil)
}

func newTestChunkUploader(t *testing.T, cm *CredentialsManager) *ChunkUploader {
	t.Helper()
	return NewChunkUploader(nil, cm)
}

// farFutureExpiry returns a unix timestamp far enough in the future that .enc files won't be treated as expired during tests (year 2286)
const farFutureExpiry = "9999999999"

func TestBuildChunkAad(t *testing.T) {
	aad1 := buildChunkAad("proj-1", "sess-1", 0, "postgres")
	aad2 := buildChunkAad("proj-1", "sess-1", 0, "postgres")
	if len(aad1) != sha256.Size {
		t.Fatalf("expected %d bytes, got %d", sha256.Size, len(aad1))
	}
	for i := range aad1 {
		if aad1[i] != aad2[i] {
			t.Fatal("identical inputs produced different AAD")
		}
	}

	variants := [][]byte{
		buildChunkAad("proj-2", "sess-1", 0, "postgres"),
		buildChunkAad("proj-1", "sess-2", 0, "postgres"),
		buildChunkAad("proj-1", "sess-1", 1, "postgres"),
		buildChunkAad("proj-1", "sess-1", 0, "aws-s3"),
	}
	for i, v := range variants {
		match := true
		for j := range v {
			if v[j] != aad1[j] {
				match = false
				break
			}
		}
		if match {
			t.Errorf("variant %d should differ from baseline but didn't", i)
		}
	}
}

func TestEncryptChunkBytes_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte(`[{"type":"input","data":"SELECT 1"}]`)
	aad := buildChunkAad("p", "s", 0, "postgres")

	ct, iv, err := encryptChunkBytes(plaintext, key, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(iv) != pamRecordingIvBytes {
		t.Fatalf("iv length: got %d, want %d", len(iv), pamRecordingIvBytes)
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithNonceSize(block, pamRecordingIvBytes)
	got, err := gcm.Open(nil, iv, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q", got)
	}
}

func TestEncryptChunkBytes_WrongKeyLength(t *testing.T) {
	_, _, err := encryptChunkBytes([]byte("x"), make([]byte, 16), nil)
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestEncryptChunkBytes_WrongAadFailsDecrypt(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("hello")
	aad := buildChunkAad("p", "s", 0, "postgres")

	ct, iv, err := encryptChunkBytes(plaintext, key, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithNonceSize(block, pamRecordingIvBytes)
	wrongAad := buildChunkAad("p", "s", 1, "postgres")
	_, err = gcm.Open(nil, iv, ct, wrongAad)
	if err == nil {
		t.Fatal("decryption should fail with wrong AAD")
	}
}

func TestWriteReadPendingChunk(t *testing.T) {
	setupTestDir(t)
	sid := "test-session-1"

	pc := &pendingChunk{
		ChunkIndex:     3,
		StartElapsedMs: 1000,
		EndElapsedMs:   2000,
		IV:             []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Ciphertext:     []byte("encrypted-data-here"),
		Sha256:         []byte("01234567890123456789012345678901"),
		StorageBackend: "postgres",
	}
	if err := writePendingChunk(sid, pc); err != nil {
		t.Fatalf("write: %v", err)
	}

	path := chunkPendingFile(sid, 3)
	got, err := readPendingChunk(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.ChunkIndex != 3 || got.StartElapsedMs != 1000 || got.EndElapsedMs != 2000 {
		t.Errorf("field mismatch: %+v", got)
	}
	if string(got.Ciphertext) != "encrypted-data-here" {
		t.Errorf("ciphertext mismatch: %q", got.Ciphertext)
	}
}

func TestScanMaxChunkIndex(t *testing.T) {
	setupTestDir(t)
	sid := "scan-test"
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	if idx := cu.scanMaxChunkIndex(sid); idx != 0 {
		t.Errorf("empty: got %d, want 0", idx)
	}

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"000000.chunk", "000003.chunk", "000007.chunk", "stale.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if idx := cu.scanMaxChunkIndex(sid); idx != 8 {
		t.Errorf("with chunks 0,3,7: got %d, want 8", idx)
	}
}

func TestLoadNextChunkIndex_CorruptFile(t *testing.T) {
	setupTestDir(t)
	sid := "corrupt-idx-test"
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	idxDir := filepath.Dir(chunkIndexFile(sid))
	if err := os.MkdirAll(idxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chunkIndexFile(sid), []byte("not-a-number"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"000000.chunk", "000002.chunk"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	idx := cu.loadNextChunkIndex(sid)
	if idx != 3 {
		t.Errorf("corrupt chunkindex with chunks 0,2: got %d, want 3", idx)
	}
}

func TestLoadNextChunkIndex_ValidFile(t *testing.T) {
	setupTestDir(t)
	sid := "valid-idx-test"
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	idxDir := filepath.Dir(chunkIndexFile(sid))
	if err := os.MkdirAll(idxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chunkIndexFile(sid), []byte("5"), 0o600); err != nil {
		t.Fatal(err)
	}

	idx := cu.loadNextChunkIndex(sid)
	if idx != 5 {
		t.Errorf("valid chunkindex=5: got %d", idx)
	}
}

func TestLoadNextChunkIndex_InMemoryCache(t *testing.T) {
	setupTestDir(t)
	sid := "cached-idx"
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)
	cu.nextChunkIndex[sid] = 42

	idx := cu.loadNextChunkIndex(sid)
	if idx != 42 {
		t.Errorf("in-memory cached value: got %d, want 42", idx)
	}
}

func TestCleanupSession_EmptyDir(t *testing.T) {
	setupTestDir(t)
	sid := "cleanup-empty"

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)
	cu.nextChunkIndex[sid] = 1

	if !cu.CleanupSession(sid) {
		t.Error("expected true for empty dir")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("dir should have been removed")
	}
}

func TestCleanupSession_WithChunks(t *testing.T) {
	setupTestDir(t)
	sid := "cleanup-chunks"

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "000000.chunk"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	if cu.CleanupSession(sid) {
		t.Error("expected false when .chunk files exist")
	}
}

func TestCleanupSession_OnlyTmpFiles(t *testing.T) {
	setupTestDir(t)
	sid := "cleanup-tmp"

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "000000.chunk.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	if !cu.CleanupSession(sid) {
		t.Error("expected true: .tmp files should not count as pending chunks")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("dir should have been removed")
	}
}

func TestCleanupSession_NoDir(t *testing.T) {
	setupTestDir(t)
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	if !cu.CleanupSession("nonexistent-session") {
		t.Error("expected true for nonexistent dir")
	}
}

func TestSaveAndLoadNextChunkIndex(t *testing.T) {
	setupTestDir(t)
	sid := "save-load-idx"

	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)
	cu.saveNextChunkIndex(sid, 7)

	cu2 := newTestChunkUploader(t, cm)
	idx := cu2.loadNextChunkIndex(sid)
	if idx != 7 {
		t.Errorf("persisted round-trip: got %d, want 7", idx)
	}
}

func TestDeletePendingChunk(t *testing.T) {
	setupTestDir(t)
	sid := "del-chunk"

	pc := &pendingChunk{
		ChunkIndex:     0,
		IV:             make([]byte, 12),
		Ciphertext:     []byte("ct"),
		Sha256:         make([]byte, 32),
		StorageBackend: "postgres",
	}
	if err := writePendingChunk(sid, pc); err != nil {
		t.Fatal(err)
	}

	path := chunkPendingFile(sid, 0)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("chunk file should exist: %v", err)
	}

	deletePendingChunk(sid, 0)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("chunk file should have been deleted")
	}
}

func TestPendingChunkJsonStability(t *testing.T) {
	pc := &pendingChunk{
		ChunkIndex:     2,
		StartElapsedMs: 5000,
		EndElapsedMs:   15000,
		IV:             []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		Ciphertext:     []byte("ciphertext-bytes"),
		Sha256:         []byte("0123456789abcdef0123456789abcdef"),
		StorageBackend: "aws-s3",
	}
	data, err := json.Marshal(pc)
	if err != nil {
		t.Fatal(err)
	}
	var decoded pendingChunk
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ChunkIndex != 2 || decoded.StorageBackend != "aws-s3" || decoded.StartElapsedMs != 5000 {
		t.Errorf("json round-trip field mismatch: %+v", decoded)
	}
	if string(decoded.Ciphertext) != string(pc.Ciphertext) {
		t.Error("ciphertext mismatch after json round-trip")
	}
}

func TestReconcileSession_NoTmpSweepWhenSecretsPresent(t *testing.T) {
	setupTestDir(t)
	sid := "reconcile-no-sweep"

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tmpFile := filepath.Join(dir, "000000.chunk.tmp")
	if err := os.WriteFile(tmpFile, []byte("in-flight"), 0o600); err != nil {
		t.Fatal(err)
	}

	cm := newTestCredentialsManager(t)
	cm.recordingSecrets[sid] = &PAMRecordingSecrets{
		SessionKey: make([]byte, 32), UploadToken: "tok",
		StorageBackend: "postgres", ProjectId: "p", SessionId: sid,
	}
	cu := newTestChunkUploader(t, cm)

	cu.ReconcileSession(sid)

	// .tmp should NOT be swept when secrets are present (could be in-flight write)
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Error(".tmp file should be preserved when secrets are present")
	}
}

func TestReconcileSession_SweepsTmpWhenNoSecrets(t *testing.T) {
	setupTestDir(t)
	sid := "reconcile-sweep"

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tmpFile := filepath.Join(dir, "000000.chunk.tmp")
	if err := os.WriteFile(tmpFile, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	cu.ReconcileSession(sid)

	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Error(".tmp file should be swept when no secrets (post-restart)")
	}
}

func TestReconcileSession_PreservesChunksWhenEncFileExists(t *testing.T) {
	setupTestDir(t)
	sid := "reconcile-preserve"

	// .enc file with far-future expiry so it's within the grace period
	encFilename := fmt.Sprintf("pam_session_%s_ssh_expires_%s.enc", sid, farFutureExpiry)
	encPath := filepath.Join(GetSessionRecordingDir(), encFilename)
	if err := os.WriteFile(encPath, []byte("session-data"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	chunkFile := filepath.Join(dir, "000000.chunk")
	if err := os.WriteFile(chunkFile, []byte(`{"chunkIndex":0}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	cu.ReconcileSession(sid)

	if _, err := os.Stat(chunkFile); os.IsNotExist(err) {
		t.Error("chunk should be preserved when .enc file exists and is not expired")
	}
}

func TestReconcileSession_DeletesChunksWhenEncFileExpiredPastGrace(t *testing.T) {
	setupTestDir(t)
	sid := "reconcile-expired"

	// .enc file with expiry well in the past (> orphanChunkGracePeriod ago)
	expiredAt := time.Now().Add(-orphanChunkGracePeriod - time.Hour).Unix()
	encFilename := fmt.Sprintf("pam_session_%s_ssh_expires_%d.enc", sid, expiredAt)
	encPath := filepath.Join(GetSessionRecordingDir(), encFilename)
	if err := os.WriteFile(encPath, []byte("session-data"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	chunkFile := filepath.Join(dir, "000000.chunk")
	if err := os.WriteFile(chunkFile, []byte(`{"chunkIndex":0}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	cu.ReconcileSession(sid)

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("chunk dir should be removed when .enc is expired past grace period")
	}
}

func TestReconcileSession_DeletesChunksWhenNoEncFile(t *testing.T) {
	setupTestDir(t)
	sid := "reconcile-orphan"

	dir := chunkQueueDir(sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	chunkFile := filepath.Join(dir, "000000.chunk")
	if err := os.WriteFile(chunkFile, []byte(`{"chunkIndex":0}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	cu.ReconcileSession(sid)

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("chunk dir should be removed when no .enc file and no secrets")
	}
}

func TestEncryptAndQueueChunk_AdvancesIndex(t *testing.T) {
	setupTestDir(t)
	sid := "enc-queue-test"

	cm := newTestCredentialsManager(t)
	cm.recordingSecrets[sid] = &PAMRecordingSecrets{
		SessionKey:     make([]byte, 32),
		UploadToken:    "tok",
		StorageBackend: "postgres",
		ProjectId:      "proj",
		SessionId:      sid,
	}
	cu := newTestChunkUploader(t, cm)

	pc1, err := cu.EncryptAndQueueChunk(sid, []byte(`["event1"]`), 0, 1000)
	if err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if pc1.ChunkIndex != 0 {
		t.Errorf("first chunk index: got %d, want 0", pc1.ChunkIndex)
	}

	pc2, err := cu.EncryptAndQueueChunk(sid, []byte(`["event2"]`), 1000, 2000)
	if err != nil {
		t.Fatalf("second chunk: %v", err)
	}
	if pc2.ChunkIndex != 1 {
		t.Errorf("second chunk index: got %d, want 1", pc2.ChunkIndex)
	}

	if _, err := os.Stat(chunkPendingFile(sid, 0)); err != nil {
		t.Error("chunk 0 file should exist")
	}
	if _, err := os.Stat(chunkPendingFile(sid, 1)); err != nil {
		t.Error("chunk 1 file should exist")
	}
}

func TestEncryptAndQueueChunk_EmptyPlaintext(t *testing.T) {
	setupTestDir(t)
	sid := "enc-empty"

	cm := newTestCredentialsManager(t)
	cm.recordingSecrets[sid] = &PAMRecordingSecrets{
		SessionKey: make([]byte, 32), StorageBackend: "postgres", ProjectId: "p", SessionId: sid,
	}
	cu := newTestChunkUploader(t, cm)

	_, err := cu.EncryptAndQueueChunk(sid, []byte{}, 0, 100)
	if err == nil {
		t.Fatal("expected error for empty plaintext")
	}
}

func TestEncryptAndQueueChunk_NoSecrets(t *testing.T) {
	setupTestDir(t)
	cm := newTestCredentialsManager(t)
	cu := newTestChunkUploader(t, cm)

	_, err := cu.EncryptAndQueueChunk("no-such-session", []byte("data"), 0, 100)
	if err == nil {
		t.Fatal("expected error when no recording secrets")
	}
}
