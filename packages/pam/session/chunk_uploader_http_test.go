package session

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

// Uses a real HTTP server so the status code travels the same path it does in production.
func newChunkUploaderAgainst(t *testing.T, status int, body string) (*ChunkUploader, *int) {
	t.Helper()

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits += 1
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	orig := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = orig })

	cm := newTestCredentialsManager(t)
	cm.recordingSecrets["sess"] = &PAMRecordingSecrets{
		SessionKey:     make([]byte, 32),
		UploadToken:    "fake-token-for-test",
		StorageBackend: storageBackendPostgres,
		ProjectId:      "proj",
		SessionId:      "sess",
	}

	return NewChunkUploader(resty.New(), cm), &hits
}

func queuedChunk(t *testing.T, sessionID string) *pendingChunk {
	t.Helper()
	pc := &pendingChunk{
		ChunkIndex:     0,
		StartElapsedMs: 0,
		EndElapsedMs:   10,
		IV:             make([]byte, 12),
		Ciphertext:     []byte("ciphertext"),
		Sha256:         make([]byte, 32),
		StorageBackend: storageBackendPostgres,
	}
	if err := writePendingChunk(sessionID, pc); err != nil {
		t.Fatal(err)
	}
	return pc
}

func TestUploadChunk_RealInvalidUploadTokenIsDropped(t *testing.T) {
	setupTestDir(t)

	cu, hits := newChunkUploaderAgainst(t, http.StatusBadRequest,
		`{"reqId":"req-x","statusCode":400,"message":"Invalid upload token","error":"PamUploadTokenHashMismatch"}`)
	pc := queuedChunk(t, "sess")

	if err := cu.UploadChunk("sess", pc); err == nil {
		t.Fatal("expected UploadChunk to surface the 400")
	}
	if *hits != 1 {
		t.Errorf("server saw %d requests, want 1", *hits)
	}
	if _, err := os.Stat(chunkPendingFile("sess", 0)); !os.IsNotExist(err) {
		t.Error("a 400 is permanent: the chunk must be dropped, not left to retry forever")
	}
}

func TestUploadChunk_RealRateLimitIsRetained(t *testing.T) {
	setupTestDir(t)

	cu, _ := newChunkUploaderAgainst(t, http.StatusTooManyRequests,
		`{"reqId":"req-y","statusCode":429,"message":"Rate limit exceeded. Please try again in 14 seconds"}`)
	pc := queuedChunk(t, "sess")

	if err := cu.UploadChunk("sess", pc); err == nil {
		t.Fatal("expected UploadChunk to surface the 429")
	}
	if _, err := os.Stat(chunkPendingFile("sess", 0)); err != nil {
		t.Errorf("a 429 is transient: the chunk must stay queued for retry: %v", err)
	}
}

func TestUploadChunk_RealServerErrorIsRetained(t *testing.T) {
	setupTestDir(t)

	cu, _ := newChunkUploaderAgainst(t, http.StatusInternalServerError, `{"statusCode":500,"message":"boom"}`)
	pc := queuedChunk(t, "sess")

	if err := cu.UploadChunk("sess", pc); err == nil {
		t.Fatal("expected UploadChunk to surface the 500")
	}
	if _, err := os.Stat(chunkPendingFile("sess", 0)); err != nil {
		t.Errorf("a 500 is transient: the chunk must stay queued for retry: %v", err)
	}
}

func TestReconcileSession_DrainsPermanentlyRejectedQueue(t *testing.T) {
	setupTestDir(t)

	cu, hits := newChunkUploaderAgainst(t, http.StatusBadRequest,
		`{"statusCode":400,"message":"Invalid upload token","error":"PamUploadTokenHashMismatch"}`)

	const queued = 5
	for i := 0; i < queued; i += 1 {
		pc := &pendingChunk{
			ChunkIndex:     i,
			IV:             make([]byte, 12),
			Ciphertext:     []byte("ciphertext"),
			Sha256:         make([]byte, 32),
			StorageBackend: storageBackendPostgres,
		}
		if err := writePendingChunk("sess", pc); err != nil {
			t.Fatal(err)
		}
	}

	cu.ReconcileSession("sess")
	if *hits != queued {
		t.Errorf("first pass made %d requests, want %d", *hits, queued)
	}

	before := *hits
	cu.ReconcileSession("sess")
	if *hits != before {
		t.Errorf("second pass made %d more requests; the queue was not drained", *hits-before)
	}

	if cu.HasPendingChunks("sess") {
		t.Error("queue still holds permanently rejected chunks")
	}
}
