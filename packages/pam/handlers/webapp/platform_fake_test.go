package webapp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type fakeChunk struct {
	body  api.ChunkMetadataRequest
	bytes []byte
}
type fakeObject struct {
	bytes   []byte
	version string
}
type strictPlatform struct {
	maxChunkJSON    int
	mu              sync.Mutex
	server          *httptest.Server
	id              string
	key             []byte
	expiry          time.Time
	startURL        string
	authMethod      string
	backend         string
	token           string
	state           string
	seq             uint64
	lease           time.Time
	leaseSeconds    int
	credentialReads int
	stopConfirmed   bool
	chunks          map[int]fakeChunk
	objects         map[int]fakeObject
	final           *api.PAMWebFinal
	manifestStatus  string
	sealed          bool
	states          []string
	events          []map[string]any
	finalized       chan struct{}
	finalOnce       sync.Once
	reject          map[string]int
	refusedCounts   map[string]int
	readinessGate   <-chan struct{}
	readinessSeen   chan struct{}
	readinessOnce   sync.Once
}

func newStrictPlatform(t *testing.T, id string, key []byte, expiry time.Time) *strictPlatform {
	t.Helper()
	p := &strictPlatform{id: id, key: key, expiry: expiry, startURL: "http://fixture.pam.local:8081/", authMethod: "none", backend: "postgres", token: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32)), state: "provisioning", leaseSeconds: 45, chunks: map[int]fakeChunk{}, objects: map[int]fakeObject{}, reject: map[string]int{}, refusedCounts: map[string]int{}, finalized: make(chan struct{}), readinessSeen: make(chan struct{})}
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}

func (p *strictPlatform) response() api.PAMWebStateResponse {
	seconds := max(0, int(time.Until(p.lease)/time.Second))
	cancel := p.state == "failed" || p.state == "stopped" || seconds == 0
	if cancel {
		seconds = 0
	}
	return api.PAMWebStateResponse{LeaseUntil: p.lease, LeaseSeconds: seconds, ExpiresAt: p.expiry, Cancel: cancel}
}

func (p *strictPlatform) renew() {
	p.lease = time.Now().Add(time.Duration(p.leaseSeconds) * time.Second)
	if p.expiry.Before(p.lease) {
		p.lease = p.expiry
	}
}
func fakeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func fakeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": message, "error": "FakePlatformError", "statusCode": status})
}

func (p *strictPlatform) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasSuffix(path, "/recording/finalize") {
		defer func() {
			p.mu.Lock()
			done := p.sealed
			p.mu.Unlock()
			if done {
				p.finalOnce.Do(func() { close(p.finalized) })
			}
		}()
	}
	if strings.HasSuffix(path, "/web-app/state") {
		var req api.PAMWebStateRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			fakeError(w, 400, "invalid report")
			return
		}
		if req.State == "recording-ready" && p.readinessGate != nil {
			p.readinessOnce.Do(func() { close(p.readinessSeen) })
			select {
			case <-p.readinessGate:
			case <-r.Context().Done():
				return
			}
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(req.Reason) > 500 || req.AllocationGen != 1 || req.UploadToken != p.token {
			fakeError(w, 400, "invalid report authority or bounds")
			return
		}
		if status := p.reject[req.State]; status != 0 {
			delete(p.reject, req.State)
			p.refusedCounts[req.State]++
			fakeError(w, status, "injected permanent report refusal")
			return
		}
		if req.ReportSeq < p.seq {
			fakeError(w, 409, "stale report")
			return
		}
		if req.ReportSeq == p.seq {
			fakeJSON(w, p.response())
			return
		}
		if p.state == "failed" && req.State != "stopped" {
			p.seq = req.ReportSeq
			fakeJSON(w, api.PAMWebStateResponse{ExpiresAt: p.expiry, LeaseUntil: time.Now(), Cancel: true})
			return
		}
		allowed := req.State == p.state || req.State == "failed" || req.State == "ending"
		switch p.state {
		case "provisioning":
			allowed = allowed || req.State == "provisioned" || req.State == "detached"
		case "provisioned":
			allowed = allowed || req.State == "recording-ready" || req.State == "detached"
		case "recording-ready":
			allowed = allowed || req.State == "active" || req.State == "detached"
		case "active":
			allowed = allowed || req.State == "detached"
		case "detached":
			allowed = allowed || req.State == "active"
		case "ending":
			allowed = allowed || req.State == "stop-unconfirmed" || req.State == "stopped"
		case "stop-unconfirmed", "failed":
			allowed = allowed || req.State == "stopped"
		case "stopped":
			allowed = req.State == "stopped"
		}
		if !allowed {
			fakeError(w, 409, "invalid state transition")
			return
		}
		noop := req.State == "detached" && (p.state == "provisioning" || p.state == "provisioned" || p.state == "recording-ready")
		if !noop {
			p.state = req.State
		}
		p.seq = req.ReportSeq
		p.states = append(p.states, req.State)
		if req.State == "stopped" {
			p.stopConfirmed = true
		}
		p.renew()
		fakeJSON(w, p.response())
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case strings.HasSuffix(path, "/pam-session-key"):
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(bytes.Repeat([]byte{8}, 32))
	case strings.HasSuffix(path, "/credentials"):
		p.renew()
		token := p.token
		if p.credentialReads > 0 {
			token = ""
		}
		p.credentialReads++
		fakeJSON(w, map[string]any{"accountType": "web-app", "connectionDetails": api.PAMWebConnectionDetails{StartURL: p.startURL, StartOrigin: "http://fixture.pam.local:8081", AllowedDestinations: []api.PAMWebDestination{{Host: "fixture.pam.local", Port: 8081, Scheme: "http"}}, ExtraDenyCIDRs: []string{}}, "credentials": map[string]string{"authMethod": p.authMethod, "username": "operator", "password": "fixture-password"}, "webAppPolicy": api.PAMWebPolicy{ReconnectGraceSeconds: 60, MaxFPS: 8, JPEGQuality: 60, MaxWidth: 1920, MaxHeight: 1200}, "expiresAt": p.expiry, "leaseUntil": p.lease, "leaseSeconds": max(0, int(time.Until(p.lease)/time.Second)), "recording": api.PAMRecordingResponse{SessionKey: base64.StdEncoding.EncodeToString(p.key), UploadToken: token, StorageBackend: p.backend, ProjectId: "proof-project", SessionId: p.id}})
	case strings.HasSuffix(path, "/chunks/presigned-put"):
		if r.Header.Get("X-Gateway-Upload-Token") != p.token {
			fakeError(w, 403, "upload token missing")
			return
		}
		var req api.ChunkPresignedPutRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.CiphertextSha256Base64 == "" {
			fakeError(w, 400, "checksum required")
			return
		}
		if object, ok := p.objects[req.ChunkIndex]; ok {
			digest := sha256.Sum256(object.bytes)
			if int64(len(object.bytes)) != req.CiphertextBytes || base64.StdEncoding.EncodeToString(digest[:]) != req.CiphertextSha256Base64 {
				fakeError(w, 409, "object conflict")
				return
			}
			var version any
			if object.version != "" && object.version != "null" {
				version = object.version
			}
			fakeJSON(w, map[string]any{"alreadyUploaded": true, "objectVersionId": version})
			return
		}
		fakeJSON(w, map[string]any{"alreadyUploaded": false, "url": fmt.Sprintf("%s/object/%d", p.server.URL, req.ChunkIndex), "method": "PUT"})
	case strings.HasPrefix(path, "/object/"):
		i, err := strconv.Atoi(strings.TrimPrefix(path, "/object/"))
		if err != nil || r.Method != http.MethodPut || r.Header.Get("If-None-Match") != "*" {
			fakeError(w, 400, "invalid object PUT")
			return
		}
		if _, exists := p.objects[i]; exists {
			fakeError(w, 412, "already exists")
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 33<<20))
		if err != nil {
			fakeError(w, 400, "read failed")
			return
		}
		digest := sha256.Sum256(b)
		if r.Header.Get("x-amz-checksum-sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
			fakeError(w, 400, "checksum mismatch")
			return
		}
		version := fmt.Sprintf("version-%d", i)
		p.objects[i] = fakeObject{bytes: b, version: version}
		w.Header().Set("x-amz-version-id", version)
	case strings.HasSuffix(path, "/chunks"):
		if r.Header.Get("X-Gateway-Upload-Token") != p.token {
			fakeError(w, 403, "upload token missing")
			return
		}
		var req api.ChunkMetadataRequest
		body, bodyErr := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		p.maxChunkJSON = max(p.maxChunkJSON, len(body))
		if len(body) > 1<<20 {
			fakeError(w, 413, "Request body is too large")
			return
		}
		if bodyErr != nil || json.Unmarshal(body, &req) != nil {
			fakeError(w, 400, "invalid chunk")
			return
		}
		var ciphertext []byte
		var err error
		if p.backend == "postgres" {
			ciphertext, err = base64.StdEncoding.DecodeString(req.Ciphertext)
		} else {
			object, exists := p.objects[req.ChunkIndex]
			if !exists || object.version != req.ObjectVersionID {
				fakeError(w, 400, "object version missing")
				return
			}
			ciphertext = object.bytes
		}
		digest := sha256.Sum256(ciphertext)
		iv, ivErr := base64.StdEncoding.DecodeString(req.IV)
		if err != nil || ivErr != nil || len(iv) != 12 || int64(len(ciphertext)) != req.CiphertextBytes || base64.StdEncoding.EncodeToString(digest[:]) != req.CiphertextSha256 {
			fakeError(w, 400, "chunk verification failed")
			return
		}
		if previous, exists := p.chunks[req.ChunkIndex]; exists {
			a, _ := json.Marshal(previous.body)
			b, _ := json.Marshal(req)
			if !bytes.Equal(a, b) {
				fakeError(w, 409, "chunk conflict")
				return
			}
			fakeJSON(w, map[string]bool{"ok": true})
			return
		}
		if p.sealed {
			fakeError(w, 409, "recording already sealed")
			return
		}
		aad := sha256.Sum256([]byte(fmt.Sprintf("proof-project|%s|%d|%s|v1", p.id, req.ChunkIndex, p.backend)))
		block, _ := aes.NewCipher(p.key)
		gcm, _ := cipher.NewGCM(block)
		plain, decryptErr := gcm.Open(nil, iv, ciphertext, aad[:])
		if decryptErr != nil {
			fakeError(w, 400, "chunk decryption failed")
			return
		}
		var batch []session.SessionEvent
		if json.Unmarshal(plain, &batch) != nil {
			fakeError(w, 400, "invalid event batch")
			return
		}
		for _, e := range batch {
			var event map[string]any
			if json.Unmarshal(e.Data, &event) != nil {
				fakeError(w, 400, "invalid web event")
				return
			}
			p.events = append(p.events, event)
		}
		p.chunks[req.ChunkIndex] = fakeChunk{body: req, bytes: bytes.Clone(ciphertext)}
		fakeJSON(w, map[string]bool{"ok": true})
	case strings.HasSuffix(path, "/recording/final"):
		var req api.PAMWebFinal
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.UploadToken != p.token {
			fakeError(w, 400, "invalid final report")
			return
		}
		if p.final != nil {
			a, _ := json.Marshal(p.final)
			b, _ := json.Marshal(req)
			if !bytes.Equal(a, b) {
				fakeError(w, 409, "final report conflict")
				return
			}
		}
		p.final = &req
		fakeJSON(w, map[string]any{"recordingFinal": req})
	case strings.HasSuffix(path, "/recording/finalize"):
		var req struct {
			ChunkCount       int    `json:"chunkCount"`
			LastEndElapsedMs int64  `json:"lastEndElapsedMs"`
			EndReason        string `json:"endReason"`
			ChainHead        string `json:"chainHeadBase64"`
			UploadToken      string `json:"uploadToken"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.UploadToken != p.token || p.final == nil {
			fakeError(w, 400, "final report required")
			return
		}
		status := "complete"
		head := make([]byte, 32)
		end := int64(0)
		if req.ChunkCount == 0 || len(p.chunks) != req.ChunkCount || p.final.ChunksEmitted != req.ChunkCount || !p.final.TerminalEventIncluded || p.final.RecordingFailed || !p.stopConfirmed {
			status = "incomplete"
		}
		for i := range req.ChunkCount {
			chunk, exists := p.chunks[i]
			if !exists || chunk.body.StartElapsedMs != end {
				status = "incomplete"
			}
			end = chunk.body.EndElapsedMs
			digest := sha256.Sum256(chunk.bytes)
			h := sha256.New()
			h.Write(head)
			h.Write(digest[:])
			head = h.Sum(nil)
		}
		if end != req.LastEndElapsedMs || end != p.final.LastEndElapsedMs {
			status = "incomplete"
		}
		for _, gap := range p.final.Gaps {
			if gap.Reason != "detached-viewer" {
				status = "incomplete"
			}
		}
		if base64.StdEncoding.EncodeToString(head) != req.ChainHead {
			status = "mismatch"
		}
		p.manifestStatus = status
		p.sealed = true
		canonical := sha256.Sum256(head)
		fakeJSON(w, map[string]any{"manifest": map[string]any{"status": status, "canonicalSha256": base64.StdEncoding.EncodeToString(canonical[:]), "signature": nil, "finalizedAt": time.Now()}})
	default:
		fakeError(w, 404, "unknown fake platform route")
	}
}
