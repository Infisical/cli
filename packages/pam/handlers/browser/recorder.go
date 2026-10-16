package browser

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"image/jpeg"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

const (
	recordedFrameInterval = 100 * time.Millisecond
	// Base64'd twice (envelope, then log entry) it's ~1.8x, under the 512 KiB Postgres chunk.
	maxRecordedJPEGBytes  = 256 * 1024
	scrollRecordInterval  = 250 * time.Millisecond
	maxRecordedTextLength = 1000
	maskedText            = "•••"
)

// Kept by name only, so the recording holds nothing an admin could reuse.
var sensitiveHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true}

// Parsed by the replay view's browserReplay.ts.
type envelopeHeader struct {
	Type      string `json:"type"`
	ElapsedMs int64  `json:"elapsedMs"`
}

type sessionStartEnvelope struct {
	envelopeHeader
	URL    string `json:"url"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

type frameEnvelope struct {
	envelopeHeader
	Seq    int    `json:"seq"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	JPEG   []byte `json:"jpeg"`
}

type httpRequestEnvelope struct {
	envelopeHeader
	ID           string            `json:"id"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers"`
	ResourceType string            `json:"resourceType"`
	BodySize     int               `json:"bodySize"`
}

type httpResponseEnvelope struct {
	envelopeHeader
	ID         string            `json:"id"`
	Status     int               `json:"status"`
	StatusText string            `json:"statusText"`
	Headers    map[string]string `json:"headers"`
	MimeType   string            `json:"mimeType"`
	BodySize   int               `json:"bodySize"`
	FromCache  bool              `json:"fromCache"`
}

type inputEnvelope struct {
	envelopeHeader
	Kind   string   `json:"kind"`
	X      *float64 `json:"x,omitempty"`
	Y      *float64 `json:"y,omitempty"`
	Target string   `json:"target,omitempty"`
	Text   string   `json:"text,omitempty"`
}

type navigationEnvelope struct {
	envelopeHeader
	URL   string `json:"url"`
	Title string `json:"title,omitempty"`
}

type blockedRequestEnvelope struct {
	envelopeHeader
	Method string `json:"method"`
	URL    string `json:"url"`
}

type dialogEnvelope struct {
	envelopeHeader
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	Accepted bool   `json:"accepted"`
}

type sessionEndEnvelope struct {
	envelopeHeader
	Reason string `json:"reason"`
}

// Shared by the stream and input loops; a nil recorder records nothing.
type recorder struct {
	logger           session.SessionLogger
	uploader         *session.SessionUploader
	sessionID        string
	priorElapsed     time.Duration // so a reconnect continues the earlier recording's clock
	started          time.Time
	credentialHeader string

	mu            sync.Mutex
	ended         bool
	frameSeq      int
	hasFrame      bool
	lastFrameHash [sha256.Size]byte
	lastFrameAt   time.Duration
	pendingFrame  *Frame
	pendingTimer  *time.Timer
	hasScrolled   bool
	lastScrollAt  time.Duration
	lastNavURL    string
	pendingNav    *navigationEnvelope
}

func newRecorder(config BrowserProxyConfig) *recorder {
	if config.SessionLogger == nil {
		return nil
	}
	r := &recorder{
		logger:       config.SessionLogger,
		uploader:     config.SessionUploader,
		sessionID:    config.SessionID,
		priorElapsed: time.Duration(config.PriorElapsedNs),
		started:      time.Now(),
	}
	if config.AuthMethod == AuthMethodHeader {
		r.credentialHeader = strings.ToLower(config.HeaderName)
	}
	return r
}

func (r *recorder) start(url string, width, height int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	elapsed := r.elapsed()
	r.writeLocked(elapsed, sessionStartEnvelope{r.header("session_start", elapsed), url, width, height})
}

func (r *recorder) frame(f Frame) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return
	}
	elapsed := r.elapsed()
	if r.hasFrame && elapsed-r.lastFrameAt < recordedFrameInterval {
		// Kept, so a burst's final screen is recorded even when nothing follows it.
		r.pendingFrame = &f
		if r.pendingTimer == nil {
			r.pendingTimer = time.AfterFunc(recordedFrameInterval-(elapsed-r.lastFrameAt), r.flushPendingFrame)
		}
		return
	}
	r.writeFrameLocked(f, elapsed)
}

func (r *recorder) flushPendingFrame() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pendingTimer = nil
	if r.ended || r.pendingFrame == nil {
		return
	}
	r.writeFrameLocked(*r.pendingFrame, r.elapsed())
}

func (r *recorder) writeFrameLocked(f Frame, elapsed time.Duration) {
	r.pendingFrame = nil
	hash := sha256.Sum256(f.JPEG)
	if r.hasFrame && hash == r.lastFrameHash {
		return
	}
	data, ok := fitJPEG(f.JPEG, maxRecordedJPEGBytes)
	if !ok {
		log.Warn().Str("sessionID", r.sessionID).Int("bytes", len(f.JPEG)).Msg("Browser frame too large to record, skipping it")
		return
	}
	r.frameSeq++
	r.hasFrame = true
	r.lastFrameHash = hash
	r.lastFrameAt = elapsed
	r.writeLocked(elapsed, frameEnvelope{r.header("frame", elapsed), r.frameSeq, f.Width, f.Height, data})
}

func (r *recorder) event(e Event) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return
	}
	elapsed := r.elapsed()
	switch e.Type {
	case EventNavigation:
		r.navigationLocked(e, elapsed)
	case EventBlockedRequest:
		r.writeLocked(elapsed, blockedRequestEnvelope{r.header("blocked_request", elapsed), e.Method, e.URL})
	case EventDialogClosed:
		r.writeLocked(elapsed, dialogEnvelope{r.header("dialog", elapsed), e.DialogType, e.Text, e.Accepted})
	case EventHTTPRequest:
		if req := e.Request; req != nil {
			r.writeLocked(elapsed, httpRequestEnvelope{
				r.header("http_request", elapsed), req.ID, req.Method, req.URL, r.redact(req.Headers), req.ResourceType, req.BodySize,
			})
		}
	case EventHTTPResponse:
		if resp := e.Response; resp != nil {
			r.writeLocked(elapsed, httpResponseEnvelope{
				r.header("http_response", elapsed), resp.ID, resp.Status, resp.StatusText, r.redact(resp.Headers), resp.MimeType, resp.BodySize, resp.FromCache,
			})
		}
	case EventEnded:
		r.endLocked(e.Text, elapsed)
	}
}

// A title arrives after its URL, so the navigation waits for it, keeping the URL's time.
func (r *recorder) navigationLocked(e Event, elapsed time.Duration) {
	if r.pendingNav != nil && r.pendingNav.URL == e.URL {
		r.pendingNav.Title = e.Title
		if e.Title != "" {
			r.flushNavigationLocked(elapsed)
		}
		return
	}
	// Later title changes on a page already recorded aren't navigations.
	if r.pendingNav == nil && e.URL == r.lastNavURL {
		return
	}
	r.flushNavigationLocked(elapsed)
	r.lastNavURL = e.URL
	navigation := navigationEnvelope{r.header("navigation", elapsed), e.URL, e.Title}
	if e.Title != "" {
		r.writeLocked(elapsed, navigation)
		return
	}
	r.pendingNav = &navigation
}

func (r *recorder) flushNavigationLocked(elapsed time.Duration) {
	if r.pendingNav == nil {
		return
	}
	r.writeLocked(elapsed, *r.pendingNav)
	r.pendingNav = nil
}

func (r *recorder) input(kind string, x, y *float64, target, text string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return
	}
	elapsed := r.elapsed()
	r.writeLocked(elapsed, inputEnvelope{r.header("input", elapsed), kind, x, y, target, text})
}

func (r *recorder) scroll(x, y float64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	elapsed := r.elapsed()
	if r.ended || (r.hasScrolled && elapsed-r.lastScrollAt < scrollRecordInterval) {
		return
	}
	r.hasScrolled = true
	r.lastScrollAt = elapsed
	r.writeLocked(elapsed, inputEnvelope{envelopeHeader: r.header("input", elapsed), Kind: "scroll", X: &x, Y: &y})
}

func (r *recorder) end(reason string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ended {
		r.endLocked(reason, r.elapsed())
	}
}

func (r *recorder) endLocked(reason string, elapsed time.Duration) {
	if r.pendingTimer != nil {
		r.pendingTimer.Stop()
		r.pendingTimer = nil
	}
	if r.pendingFrame != nil {
		r.writeFrameLocked(*r.pendingFrame, elapsed)
	}
	r.flushNavigationLocked(elapsed)
	r.writeLocked(elapsed, sessionEndEnvelope{r.header("session_end", elapsed), reason})
	r.ended = true
}

func (r *recorder) elapsed() time.Duration {
	return r.priorElapsed + time.Since(r.started)
}

func (r *recorder) header(envelopeType string, elapsed time.Duration) envelopeHeader {
	return envelopeHeader{Type: envelopeType, ElapsedMs: elapsed.Milliseconds()}
}

// Under mu, so records reach the log in elapsed order; the uploader's chunk ranges rely on it.
func (r *recorder) writeLocked(elapsed time.Duration, envelope any) {
	data, err := json.Marshal(envelope)
	if err != nil {
		log.Warn().Err(err).Str("sessionID", r.sessionID).Msg("Failed to encode browser recording event")
		return
	}
	if err := r.logger.LogSessionEvent(session.SessionEvent{
		Timestamp:   time.Now(),
		EventType:   session.SessionEventBrowser,
		ChannelType: session.SessionChannelBrowser,
		Data:        data,
		ElapsedTime: elapsed.Seconds(),
	}); err != nil {
		log.Warn().Err(err).Str("sessionID", r.sessionID).Msg("Failed to record browser event")
		return
	}
	if r.uploader != nil {
		r.uploader.RecordEmittedElapsedNs(r.sessionID, uint64(elapsed.Nanoseconds()))
	}
}

func (r *recorder) redact(headers map[string]string) map[string]string {
	redacted := make(map[string]string, len(headers))
	for name, value := range headers {
		lower := strings.ToLower(name)
		if sensitiveHeaders[lower] || (r.credentialHeader != "" && lower == r.credentialHeader) {
			value = maskedText
		}
		redacted[name] = value
	}
	return redacted
}

func recordedText(text string, element Element, known bool) string {
	if text == "" {
		return ""
	}
	// A field that can't be identified might be a password field.
	if !known || element.Masked {
		return maskedText
	}
	if len(text) > maxRecordedTextLength {
		return strings.ToValidUTF8(text[:maxRecordedTextLength], "")
	}
	return text
}

func fitJPEG(data []byte, limit int) ([]byte, bool) {
	if len(data) <= limit {
		return data, true
	}
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	for _, quality := range []int{50, 30} {
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err == nil && buf.Len() <= limit {
			return buf.Bytes(), true
		}
	}
	return nil, false
}
