package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

func TestWebRecordingRecoveryAndFinalization(t *testing.T) {
	prior := GetSessionRecordingDir()
	SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { SetSessionRecordingPath(prior) })
	id := "33333333-3333-4333-8333-333333333333"
	key := bytes.Repeat([]byte{7}, 32)
	logger, err := NewSessionLogger(id, base64.StdEncoding.EncodeToString(key), time.Now().Add(time.Hour), ResourceTypeWebApp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.LogSessionEvent(SessionEvent{EventType: SessionEventWeb, ChannelType: SessionChannelWeb, Data: []byte(`{"type":"lifecycle","phase":"ended"}`), ElapsedTime: 1.25}); err != nil {
		t.Fatal(err)
	}
	logger.Close()
	info, err := FindSessionFileBySessionID(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(webSecretsPath(id), []byte("retained")); err != nil {
		t.Fatal(err)
	}
	var firstCiphertext string
	metadataCalls, finalizeCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/v1/pam/sessions/" + id + "/chunks":
			var body api.ChunkMetadataRequest
			if json.NewDecoder(req.Body).Decode(&body) != nil {
				t.Error("bad metadata")
				w.WriteHeader(400)
				return
			}
			ciphertext, _ := base64.StdEncoding.DecodeString(body.Ciphertext)
			digest := sha256.Sum256(ciphertext)
			if body.CiphertextSha256 != base64.StdEncoding.EncodeToString(digest[:]) {
				t.Error("wrong ciphertext digest")
			}
			metadataCalls++
			if firstCiphertext == "" {
				firstCiphertext = body.Ciphertext
			} else if firstCiphertext != body.Ciphertext {
				t.Error("retry changed ciphertext")
			}
			if metadataCalls == 1 {
				w.WriteHeader(503)
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case "/v1/pam/sessions/" + id + "/recording/final":
			var final api.PAMWebFinal
			_ = json.NewDecoder(req.Body).Decode(&final)
			if final.ChunksEmitted != 1 || final.LastEndElapsedMs != 1250 || !final.TerminalEventIncluded || !final.RecordingFailed {
				t.Errorf("wrong terminal boundary: %+v", final)
			}
			_, _ = w.Write([]byte(`{}`))
		case "/v1/pam/sessions/" + id + "/recording/finalize":
			finalizeCalls++
			if finalizeCalls == 1 {
				w.WriteHeader(503)
				return
			}
			_, _ = w.Write([]byte(`{"manifest":{"status":"incomplete"}}`))
		default:
			t.Errorf("unexpected route %s", req.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	oldURL := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = oldURL })
	r := &WebRecording{id: id, client: resty.New(), secrets: &PAMRecordingSecrets{SessionKey: key, UploadToken: "token", StorageBackend: storageBackendPostgres, ProjectId: "project"}, state: webRecordingState{Filename: info.Filename, ChainHead: make([]byte, 32), ObjectVersions: map[int]string{}}}
	if err := r.Flush(t.Context()); err == nil {
		t.Fatal("lost metadata response not surfaced")
	}
	data, err := os.ReadFile(webRecordingPath(id))
	if err != nil {
		t.Fatal(err)
	}
	var restored webRecordingState
	if json.Unmarshal(data, &restored) != nil || restored.Pending == nil || restored.Offset != 0 {
		t.Fatal("pending ciphertext and offset not durable")
	}
	r = &WebRecording{id: id, client: r.client, secrets: r.secrets, state: restored}
	if err := r.Finish(api.PAMWebFinal{TerminalEventIncluded: true, RecordingFailed: true}, "recording-failed"); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(t.Context()); err == nil {
		t.Fatal("finalize failure not retained")
	}
	if _, err := os.Stat(webSecretsPath(id)); err != nil {
		t.Fatal("secrets removed before finalize acknowledgement")
	}
	if r.state.ChunkCount != 1 || r.state.Pending != nil || r.state.Offset == 0 {
		t.Fatal("recovery advanced incorrectly")
	}
	digest := sha256.Sum256(mustBase64(t, firstCiphertext))
	chain := sha256.Sum256(append(make([]byte, 32), digest[:]...))
	if !bytes.Equal(r.state.ChainHead, chain[:]) {
		t.Fatal("chain differs")
	}
	if err := r.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(webSecretsPath(id)); !os.IsNotExist(err) {
		t.Fatal("secrets retained after acknowledged finalize")
	}
	if _, err := os.Stat(filepath.Join(GetSessionRecordingDir(), info.Filename)); !os.IsNotExist(err) {
		t.Fatal("spool retained after acknowledged finalize")
	}
}

func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWebS3CreateOnlyChecksumAndVersion(t *testing.T) {
	data := []byte("ciphertext")
	digest := sha256.Sum256(data)
	for _, version := range []string{"", "null", "immutable-version"} {
		t.Run(version, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") != "*" || r.Header.Get("x-amz-checksum-sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
					t.Error("missing required upload headers")
				}
				w.Header().Set("x-amz-version-id", version)
			}))
			defer server.Close()
			got, err := putWebCiphertext(t.Context(), server.URL, data, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			want := version
			if want == "null" {
				want = ""
			}
			if got != want {
				t.Fatalf("version %q want %q", got, want)
			}
		})
	}
}

func TestWebS3RecoversLostPutReceipt(t *testing.T) {
	prior := GetSessionRecordingDir()
	SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { SetSessionRecordingPath(prior) })
	id := "44444444-4444-4444-8444-444444444444"
	key := bytes.Repeat([]byte{21}, 32)
	logger, err := NewSessionLogger(id, base64.StdEncoding.EncodeToString(key), time.Now().Add(time.Hour), ResourceTypeWebApp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.LogSessionEvent(SessionEvent{EventType: SessionEventWeb, ChannelType: SessionChannelWeb, Data: []byte(`{"type":"lifecycle","phase":"ended"}`), ElapsedTime: 2}); err != nil {
		t.Fatal(err)
	}
	logger.Close()
	info, _ := FindSessionFileBySessionID(id)
	var mu sync.Mutex
	var uploaded []byte
	puts := 0
	metadata := false
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method == http.MethodPut {
			b, _ := io.ReadAll(req.Body)
			mu.Lock()
			uploaded = b
			puts++
			mu.Unlock()
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close()
			return
		}
		if strings.HasSuffix(req.URL.Path, "/presigned-put") {
			var request api.ChunkPresignedPutRequest
			_ = json.NewDecoder(req.Body).Decode(&request)
			if request.CiphertextSha256Base64 == "" {
				t.Error("missing checksum contract")
			}
			mu.Lock()
			exists := len(uploaded) > 0
			ct := bytes.Clone(uploaded)
			mu.Unlock()
			if exists {
				digest := sha256.Sum256(ct)
				if request.CiphertextSha256Base64 != base64.StdEncoding.EncodeToString(digest[:]) {
					t.Error("retry changed encrypted bytes")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"alreadyUploaded": true, "objectVersionId": "version-1"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"url": server.URL + "/object", "method": "PUT", "alreadyUploaded": false})
			return
		}
		if strings.HasSuffix(req.URL.Path, "/chunks") {
			var body api.ChunkMetadataRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			if body.ObjectVersionID != "version-1" {
				t.Error("recovered version missing")
			}
			b, _ := os.ReadFile(webRecordingPath(id))
			var durable webRecordingState
			_ = json.Unmarshal(b, &durable)
			if durable.Pending == nil || !durable.Pending.PutDone || durable.Pending.Version != "version-1" {
				t.Error("receipt not persisted before metadata")
			}
			metadata = true
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	priorURL := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = priorURL })
	r := &WebRecording{id: id, client: resty.New(), secrets: &PAMRecordingSecrets{SessionKey: key, UploadToken: "token", StorageBackend: storageBackendAwsS3, ProjectId: "project"}, state: webRecordingState{Filename: info.Filename, ChainHead: make([]byte, 32), ObjectVersions: map[int]string{}}}
	if err := r.Flush(t.Context()); err == nil {
		t.Fatal("lost PUT response not surfaced")
	}
	b, _ := os.ReadFile(webRecordingPath(id))
	var state webRecordingState
	_ = json.Unmarshal(b, &state)
	if state.Pending == nil || state.Pending.PutDone {
		t.Fatal("lost receipt was not recoverable")
	}
	r = &WebRecording{id: id, client: r.client, secrets: r.secrets, state: state}
	if err := r.Finish(api.PAMWebFinal{TerminalEventIncluded: true}, "user-ended"); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if puts != 1 || !metadata || !r.state.Finalized {
		t.Fatalf("recovery did not finalize without overwriting: puts=%d metadata=%v", puts, metadata)
	}
}

func TestWebRecording413IsPermanentAndFinalizesFailedPrefix(t *testing.T) {
	prior := GetSessionRecordingDir()
	SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { SetSessionRecordingPath(prior) })
	id := "77777777-7777-4777-8777-777777777777"
	key := bytes.Repeat([]byte{13}, 32)
	logger, err := NewSessionLogger(id, base64.StdEncoding.EncodeToString(key), time.Now().Add(time.Minute), ResourceTypeWebApp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.LogSessionEvent(SessionEvent{EventType: SessionEventWeb, Data: []byte(`{"type":"lifecycle","phase":"ended"}`), ElapsedTime: 1}); err != nil {
		t.Fatal(err)
	}
	info, err := FindSessionFileBySessionID(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(webSecretsPath(id), []byte("retained encrypted secrets")); err != nil {
		t.Fatal(err)
	}
	chunkCalls, finalCalls, finalizeCalls := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(req.URL.Path, "/chunks"):
			chunkCalls++
			w.WriteHeader(413)
			_, _ = w.Write([]byte(`{"message":"Request body is too large","error":"PayloadTooLarge"}`))
		case strings.HasSuffix(req.URL.Path, "/recording/final"):
			finalCalls++
			var final api.PAMWebFinal
			_ = json.NewDecoder(req.Body).Decode(&final)
			if !final.RecordingFailed || final.TerminalEventIncluded || final.ChunksEmitted != 0 {
				t.Errorf("refused chunk claimed as recorded: %+v", final)
			}
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(req.URL.Path, "/recording/finalize"):
			finalizeCalls++
			_, _ = w.Write([]byte(`{"manifest":{"status":"incomplete"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	oldURL := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = oldURL })
	r := &WebRecording{id: id, client: resty.New(), logger: logger, secrets: &PAMRecordingSecrets{SessionKey: key, UploadToken: "token", StorageBackend: storageBackendPostgres, ProjectId: "project"}, state: webRecordingState{Filename: info.Filename, ChainHead: make([]byte, 32), ObjectVersions: map[int]string{}}}
	err = r.Flush(t.Context())
	response, ok := errors.AsType[*api.APIError](err)
	if !ok || response.StatusCode != 413 || !strings.Contains(response.ResponseBody, "Request body is too large") {
		t.Fatalf("missing refusal diagnostic: %v", err)
	}
	if r.state.UploadRefusal == "" || !r.uploadRefused.Load() {
		t.Fatal("413 refusal was not durable")
	}
	if err := r.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if chunkCalls != 1 {
		t.Fatal("413 chunk was retried")
	}
	if err := r.LogSessionEvent(SessionEvent{EventType: SessionEventWeb, Data: []byte(`{"type":"heartbeat"}`), ElapsedTime: 2}); err == nil {
		t.Fatal("permanent upload failure did not reach supervisor")
	}
	logger.Close()
	if err := r.Finish(api.PAMWebFinal{TerminalEventIncluded: true}, "recording-failed"); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if finalCalls != 1 || finalizeCalls != 1 || !r.state.Finalized {
		t.Fatal("failed prefix did not finalize")
	}
	for _, path := range []string{webSecretsPath(id), filepath.Join(GetSessionRecordingDir(), info.Filename)} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unuploaded evidence removed: %v", err)
		}
	}
}

func TestWebRecordingChunkSizingPerBackend(t *testing.T) {
	for _, backend := range []string{storageBackendPostgres, storageBackendAwsS3} {
		t.Run(backend, func(t *testing.T) {
			prior := GetSessionRecordingDir()
			SetSessionRecordingPath(t.TempDir())
			t.Cleanup(func() { SetSessionRecordingPath(prior) })
			id := "88888888-8888-4888-8888-888888888888"
			key := bytes.Repeat([]byte{14}, 32)
			logger, err := NewSessionLogger(id, base64.StdEncoding.EncodeToString(key), time.Now().Add(time.Minute), ResourceTypeWebApp, nil)
			if err != nil {
				t.Fatal(err)
			}
			for i := range 40 {
				if err := logger.LogSessionEvent(SessionEvent{EventType: SessionEventWeb, Data: bytes.Repeat([]byte{'x'}, 200<<10), ElapsedTime: float64(i + 1)}); err != nil {
					t.Fatal(err)
				}
			}
			logger.Close()
			info, err := FindSessionFileBySessionID(id)
			if err != nil {
				t.Fatal(err)
			}
			objects := map[int][]byte{}
			calls, events, maxPlain := 0, 0, 0
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if req.Method == http.MethodPut {
					index, _ := strconv.Atoi(strings.TrimPrefix(req.URL.Path, "/object/"))
					objects[index], _ = io.ReadAll(req.Body)
					_, _ = w.Write([]byte(`{}`))
					return
				}
				if strings.HasSuffix(req.URL.Path, "/presigned-put") {
					var body api.ChunkPresignedPutRequest
					_ = json.NewDecoder(req.Body).Decode(&body)
					_ = json.NewEncoder(w).Encode(map[string]any{"url": server.URL + "/object/" + strconv.Itoa(body.ChunkIndex), "method": "PUT"})
					return
				}
				data, err := io.ReadAll(io.LimitReader(req.Body, (1<<20)+1))
				if err != nil {
					t.Error(err)
				}
				if len(data) > 1<<20 {
					t.Errorf("chunk JSON exceeds nginx ceiling: %d", len(data))
				}
				var body api.ChunkMetadataRequest
				if json.Unmarshal(data, &body) != nil {
					t.Error("invalid chunk metadata")
				}
				ct, _ := base64.StdEncoding.DecodeString(body.Ciphertext)
				if backend == storageBackendAwsS3 {
					ct = objects[body.ChunkIndex]
				}
				iv, _ := base64.StdEncoding.DecodeString(body.IV)
				block, _ := aes.NewCipher(key)
				gcm, _ := cipher.NewGCM(block)
				plain, err := gcm.Open(nil, iv, ct, buildChunkAad("project", id, body.ChunkIndex, backend))
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				limit := 8 << 20
				if backend == storageBackendPostgres {
					limit = pamPostgresMaxPlaintextBytes
				}
				if len(plain) > limit {
					t.Errorf("%s plaintext exceeds cap: %d", backend, len(plain))
				}
				maxPlain = max(maxPlain, len(plain))
				var batch []SessionEvent
				if json.Unmarshal(plain, &batch) != nil {
					t.Error("split inside an event")
				}
				events += len(batch)
				calls++
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()
			oldURL := config.INFISICAL_URL
			config.INFISICAL_URL = server.URL
			t.Cleanup(func() { config.INFISICAL_URL = oldURL })
			r := &WebRecording{id: id, client: resty.New(), secrets: &PAMRecordingSecrets{SessionKey: key, UploadToken: "token", StorageBackend: backend, ProjectId: "project"}, state: webRecordingState{Filename: info.Filename, ChainHead: make([]byte, 32), ObjectVersions: map[int]string{}}}
			if err := r.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
			if events != 40 || calls < 2 || r.state.ChunkCount != calls {
				t.Fatalf("event split mismatch: events=%d chunks=%d", events, calls)
			}
			if backend == storageBackendAwsS3 && maxPlain <= pamPostgresMaxPlaintextBytes {
				t.Fatal("S3 did not retain its larger target")
			}
		})
	}
}
