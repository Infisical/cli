package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type webPending struct {
	PutDone    bool         `json:"putDone"`
	Chunk      pendingChunk `json:"chunk"`
	NextOffset int64        `json:"nextOffset"`
	Version    string       `json:"version,omitempty"`
}

type webRecordingState struct {
	UploadRefusal string `json:"uploadRefusal,omitempty"`
	FinalRefusal  string `json:"finalRefusal,omitempty"`

	Filename         string           `json:"filename"`
	Offset           int64            `json:"offset"`
	ChunkCount       int              `json:"chunkCount"`
	ChainHead        []byte           `json:"chainHead"`
	LastEndElapsedMs int64            `json:"lastEndElapsedMs"`
	ObjectVersions   map[int]string   `json:"objectVersions"`
	Pending          *webPending      `json:"pending,omitempty"`
	PendingFinalize  *api.PAMWebFinal `json:"pendingFinalize,omitempty"`
	EndReason        string           `json:"endReason,omitempty"`
	FinalReported    bool             `json:"finalReported"`
	Finalized        bool             `json:"finalized"`
}

type WebRecording struct {
	uploadRefused atomic.Bool
	credentials   *CredentialsManager

	finished chan struct{}

	count atomic.Int64

	mu      sync.Mutex
	id      string
	state   webRecordingState
	secrets *PAMRecordingSecrets
	client  *resty.Client
	logger  *EncryptedSessionLogger
}

func webRecordingPath(id string) string {
	return filepath.Join(GetSessionRecordingDir(), "webapp", id+".recording")
}

func NewWebRecording(id string, expiry time.Time, cm *CredentialsManager, client *resty.Client) (*WebRecording, error) {
	secrets := cm.GetRecordingSecrets(id)
	if secrets == nil || len(secrets.SessionKey) != 32 || secrets.UploadToken == "" {
		return nil, errors.New("web recording secrets required")
	}
	logger, err := NewSessionLogger(id, base64.StdEncoding.EncodeToString(secrets.SessionKey), expiry, ResourceTypeWebApp, nil)
	if err != nil {
		return nil, err
	}
	dir, err := os.Open(GetSessionRecordingDir())
	if err != nil {
		logger.Close()
		return nil, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		logger.Close()
		return nil, err
	}
	info, err := FindSessionFileBySessionID(id)
	if err != nil {
		logger.Close()
		return nil, err
	}
	r := &WebRecording{finished: make(chan struct{}), credentials: cm, id: id, client: client, secrets: secrets, logger: logger, state: webRecordingState{Filename: info.Filename, ChainHead: make([]byte, 32), ObjectVersions: map[int]string{}}}
	if err := r.persist(); err != nil {
		logger.Close()
		return nil, err
	}
	go r.retryLoop()
	return r, nil
}

func (r *WebRecording) persist() error {
	state := r.state
	if state.PendingFinalize != nil {
		final := *state.PendingFinalize
		final.UploadToken = ""
		state.PendingFinalize = &final
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return AtomicWrite(webRecordingPath(r.id), b)
}

func (r *WebRecording) LogSessionEvent(event SessionEvent) error {
	if err := r.logger.LogSessionEvent(event); err != nil {
		return err
	}
	if r.uploadRefused.Load() {
		return errors.New("recording chunk permanently refused")
	}
	return nil
}
func (r *WebRecording) Close() error    { return r.logger.Close() }
func (r *WebRecording) ChunkCount() int { return int(r.count.Load()) }

func (r *WebRecording) Finish(final api.PAMWebFinal, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	final.UploadToken = r.secrets.UploadToken
	r.state.PendingFinalize = &final
	r.state.EndReason = reason
	return r.persist()
}

func (r *WebRecording) Done() <-chan struct{} { return r.finished }

func (r *WebRecording) retryLoop() {
	defer close(r.finished)
	delay := 5 * time.Second
	for {
		time.Sleep(delay)
		err := r.Flush(context.Background())
		if err != nil {
			event := log.Warn().Str("sessionId", r.id)
			if response, ok := errors.AsType[*api.APIError](err); ok {
				body := strings.ReplaceAll(response.ResponseBody, r.secrets.UploadToken, "[redacted]")
				if len(body) > 4096 {
					body = body[:4096]
				}
				event.Int("status", response.StatusCode).Str("responseBody", body).Msg("PAM recording upload failed")
			} else {
				event.Err(err).Msg("PAM recording upload failed")
			}
		}
		r.mu.Lock()
		finished := r.state.Finalized || r.state.FinalRefusal != ""
		r.mu.Unlock()
		if finished {
			return
		}
		if err != nil {
			delay = min(delay*2, 5*time.Minute)
		} else {
			delay = 5 * time.Second
		}
	}
}

func (r *WebRecording) post(ctx context.Context, route string, body any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return api.CallPAMWebReport(ctx, r.client, r.id, route, body, nil)
}

func (r *WebRecording) Flush(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.Finalized || r.state.FinalRefusal != "" {
		return nil
	}
	for r.state.UploadRefusal == "" {
		if r.state.Pending == nil {
			limit := 8 << 20
			if r.secrets.StorageBackend == storageBackendPostgres {
				limit = pamPostgresMaxPlaintextBytes
			}
			payload, offset, end, _, err := readFromOffset(r.state.Filename, base64.StdEncoding.EncodeToString(r.secrets.SessionKey), r.state.Offset, limit)
			if err != nil {
				return err
			}
			if len(payload) > limit {
				return r.refuseChunk(errors.New("recording event exceeds chunk plaintext limit"))
			}
			if len(payload) == 0 {
				break
			}
			aad := buildChunkAad(r.secrets.ProjectId, r.id, r.state.ChunkCount, r.secrets.StorageBackend)
			ct, iv, err := encryptChunkBytes(payload, r.secrets.SessionKey, aad)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(ct)
			r.state.Pending = &webPending{NextOffset: offset, Chunk: pendingChunk{ChunkIndex: r.state.ChunkCount, StartElapsedMs: r.state.LastEndElapsedMs, EndElapsedMs: max(r.state.LastEndElapsedMs, end), IV: iv, Ciphertext: ct, Sha256: digest[:], StorageBackend: r.secrets.StorageBackend}}
			if err := r.persist(); err != nil {
				return err
			}
		}
		pending := r.state.Pending
		pc := &pending.Chunk
		if pc.StorageBackend == storageBackendAwsS3 && !pending.PutDone {
			presigned, err := api.CallPAMSessionChunkPresignedPutContext(ctx, r.client, r.id, r.secrets.UploadToken, api.ChunkPresignedPutRequest{ChunkIndex: pc.ChunkIndex, CiphertextBytes: int64(len(pc.Ciphertext)), CiphertextSha256Base64: base64.StdEncoding.EncodeToString(pc.Sha256)})
			if err != nil {
				return err
			}
			version := presigned.ObjectVersionID
			if version == "null" {
				version = ""
			}
			if !presigned.AlreadyUploaded {
				version, err = putWebCiphertext(ctx, presigned.URL, pc.Ciphertext, pc.Sha256)
				if err != nil {
					return err
				}
			}
			pending.Version = version
			pending.PutDone = true
			if err := r.persist(); err != nil {
				return err
			}
		}
		body := api.ChunkMetadataRequest{ChunkIndex: pc.ChunkIndex, StartElapsedMs: pc.StartElapsedMs, EndElapsedMs: pc.EndElapsedMs, CiphertextSha256: base64.StdEncoding.EncodeToString(pc.Sha256), CiphertextBytes: int64(len(pc.Ciphertext)), IV: base64.StdEncoding.EncodeToString(pc.IV), ObjectVersionID: pending.Version}
		if pc.StorageBackend == storageBackendPostgres {
			body.Ciphertext = base64.StdEncoding.EncodeToString(pc.Ciphertext)
		} else if pc.StorageBackend != storageBackendAwsS3 {
			return errors.New("unsupported web recording storage")
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(encoded) > 32<<20 {
			return r.refuseChunk(errors.New("recording chunk JSON exceeds 32 MiB"))
		}
		if err := api.CallPAMSessionChunkMetadataContext(ctx, r.client, r.id, r.secrets.UploadToken, body); err != nil {
			if response, ok := errors.AsType[*api.APIError](err); ok && response.StatusCode == http.StatusRequestEntityTooLarge {
				return r.refuseChunk(err)
			}
			return err
		}
		h := sha256.New()
		h.Write(r.state.ChainHead)
		h.Write(pc.Sha256)
		r.state.ChainHead = h.Sum(nil)
		r.state.Offset = pending.NextOffset
		r.state.LastEndElapsedMs = pc.EndElapsedMs
		r.state.ChunkCount++
		r.count.Store(int64(r.state.ChunkCount))
		if pending.Version != "" {
			r.state.ObjectVersions[pc.ChunkIndex] = pending.Version
		}
		r.state.Pending = nil
		if err := r.persist(); err != nil {
			return err
		}
	}
	if r.state.PendingFinalize == nil {
		return nil
	}
	final := r.state.PendingFinalize
	if r.state.UploadRefusal != "" {
		final.RecordingFailed = true
		final.TerminalEventIncluded = false
	}
	final.UploadToken = r.secrets.UploadToken
	final.ChunksEmitted = r.state.ChunkCount
	final.LastEndElapsedMs = r.state.LastEndElapsedMs
	if final.Gaps == nil {
		final.Gaps = []api.PAMWebGap{}
	}
	if err := r.persist(); err != nil {
		return err
	}
	if !r.state.FinalReported {
		if err := r.post(ctx, "recording/final", final); err != nil {
			return r.terminalRefusal("recording/final", err)
		}
		r.state.FinalReported = true
		if err := r.persist(); err != nil {
			return err
		}
	}
	if err := r.post(ctx, "recording/finalize", map[string]any{"chunkCount": r.state.ChunkCount, "lastEndElapsedMs": r.state.LastEndElapsedMs, "endReason": r.state.EndReason, "chainHeadBase64": base64.StdEncoding.EncodeToString(r.state.ChainHead), "uploadToken": r.secrets.UploadToken}); err != nil {
		return r.terminalRefusal("recording/finalize", err)
	}
	r.state.Finalized = true
	if err := r.persist(); err != nil {
		return err
	}
	// The acknowledged manifest is the boundary after which recovery secrets can be discarded.
	if r.state.UploadRefusal == "" {
		if r.credentials != nil {
			r.credentials.CleanupSessionCredentials(r.id)
		}
		_ = os.Remove(webSecretsPath(r.id))
		_ = os.Remove(filepath.Join(GetSessionRecordingDir(), r.state.Filename))
	} else if r.credentials != nil {
		r.credentials.InvalidateSessionCredentials(r.id)
	}
	r.cleanupLifecycle()
	return nil
}

func (r *WebRecording) refuseChunk(err error) error {
	r.state.UploadRefusal = err.Error()
	r.uploadRefused.Store(true)
	if persistErr := r.persist(); persistErr != nil {
		return persistErr
	}
	return err
}

func putWebCiphertext(ctx context.Context, url string, ciphertext, digest []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(ciphertext))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(digest))
	req.Header.Set("If-None-Match", "*")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("create-only recording PUT returned %d", resp.StatusCode)
	}
	version := resp.Header.Get("x-amz-version-id")
	if version == "null" {
		version = ""
	}
	return version, nil
}

func ResumeWebRecordings(cm *CredentialsManager, client *resty.Client) error {
	entries, err := os.ReadDir(filepath.Join(GetSessionRecordingDir(), "webapp"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".recording")
		if !ok {
			continue
		}
		if _, err := os.Stat(filepath.Join(GetSessionRecordingDir(), "webapp", id+".alloc")); err == nil {
			continue
		}
		b, err := os.ReadFile(webRecordingPath(id))
		if err != nil {
			return err
		}
		var state webRecordingState
		if err := json.Unmarshal(b, &state); err != nil {
			return err
		}
		if state.Finalized || state.FinalRefusal != "" || state.PendingFinalize == nil {
			continue
		}
		if err := cm.loadWebSecrets(id); err != nil {
			return err
		}
		r := &WebRecording{finished: make(chan struct{}), credentials: cm, id: id, state: state, secrets: cm.GetRecordingSecrets(id), client: client}
		r.count.Store(int64(state.ChunkCount))
		r.uploadRefused.Store(state.UploadRefusal != "")
		go r.retryLoop()
	}
	return nil
}

func RecoverWebRecording(id string, cm *CredentialsManager, client *resty.Client, final api.PAMWebFinal, reason string) (*WebRecording, error) {
	b, err := os.ReadFile(webRecordingPath(id))
	if err != nil {
		return nil, err
	}
	var state webRecordingState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, err
	}
	if state.Finalized || state.FinalRefusal != "" {
		r := &WebRecording{id: id}
		r.cleanupLifecycle()
		return nil, nil
	}
	if cm.GetRecordingSecrets(id) == nil {
		if err := cm.loadWebSecrets(id); err != nil {
			return nil, err
		}
	}
	r := &WebRecording{finished: make(chan struct{}), credentials: cm, id: id, state: state, secrets: cm.GetRecordingSecrets(id), client: client}
	r.count.Store(int64(state.ChunkCount))
	r.uploadRefused.Store(state.UploadRefusal != "")
	if state.PendingFinalize == nil {
		if err := r.Finish(final, reason); err != nil {
			return nil, err
		}
	}
	go r.retryLoop()
	return r, nil
}

func (r *WebRecording) cleanupLifecycle() {
	path := filepath.Join(GetSessionRecordingDir(), "webapp", r.id+".alloc")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var allocation struct {
		State   string            `json:"state"`
		Pending []json.RawMessage `json:"pendingReports"`
	}
	if json.Unmarshal(b, &allocation) != nil || allocation.State != "stopped" || len(allocation.Pending) != 0 {
		return
	}
	_ = os.Remove(filepath.Join(GetSessionRecordingDir(), "webapp", r.id+".tomb"))
	_ = os.Remove(path)
}

func (r *WebRecording) terminalRefusal(route string, err error) error {
	status, final := api.PAMReportRefusal(err)
	if !final {
		return err
	}
	r.state.FinalRefusal = fmt.Sprintf("%s: HTTP %d", route, status)
	r.state.PendingFinalize = nil
	if persistErr := r.persist(); persistErr != nil {
		return persistErr
	}
	log.Warn().Int("status", status).Str("route", route).Str("sessionId", r.id).Msg("PAM recording finalization refused")
	if r.credentials != nil {
		r.credentials.InvalidateSessionCredentials(r.id)
	}
	r.cleanupLifecycle()
	return err
}
