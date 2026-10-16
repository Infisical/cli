package browser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/stretchr/testify/require"
)

type recordingLogger struct {
	mu     sync.Mutex
	events []session.SessionEvent
}

func (l *recordingLogger) LogEntry(entry session.SessionLogEntry) error { return nil }

func (l *recordingLogger) LogSessionEvent(event session.SessionEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	return nil
}

func (l *recordingLogger) LogHttpEvent(event session.HttpEvent) error { return nil }

func (l *recordingLogger) Close() error { return nil }

func (l *recordingLogger) envelopes(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	envelopes := make([]map[string]any, 0, len(l.events))
	for _, event := range l.events {
		require.Equal(t, session.SessionEventBrowser, event.EventType)
		require.Equal(t, session.SessionChannelBrowser, event.ChannelType)
		var envelope map[string]any
		require.NoError(t, json.Unmarshal(event.Data, &envelope))
		envelopes = append(envelopes, envelope)
	}
	return envelopes
}

func (l *recordingLogger) ofType(t *testing.T, envelopeType string) []map[string]any {
	t.Helper()
	var matching []map[string]any
	for _, envelope := range l.envelopes(t) {
		if envelope["type"] == envelopeType {
			matching = append(matching, envelope)
		}
	}
	return matching
}

func testJPEG(t *testing.T, fill color.Color) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for x := 0; x < 64; x++ {
		for y := 0; y < 64; y++ {
			img.Set(x, y, fill)
		}
	}
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, nil))
	return buf.Bytes()
}

func TestRecorderWritesTheEnvelopesTheReplayReads(t *testing.T) {
	logger := &recordingLogger{}
	prior := 90 * time.Second
	rec := newRecorder(BrowserProxyConfig{
		SessionID:      "recorder-test",
		SessionLogger:  logger,
		AuthMethod:     AuthMethodHeader,
		HeaderName:     "X-Api-Key",
		PriorElapsedNs: uint64(prior),
	})
	white := testJPEG(t, color.White)

	rec.start("https://app.internal/", 1280, 800)
	rec.frame(Frame{JPEG: white, Width: 1280, Height: 800})
	rec.event(Event{Type: EventNavigation, URL: "https://app.internal/home"})
	rec.event(Event{Type: EventNavigation, URL: "https://app.internal/home", Title: "Home"})
	rec.event(Event{Type: EventNavigation, URL: "https://app.internal/home", Title: "(1) Home"})
	rec.event(Event{Type: EventHTTPRequest, Request: &HTTPRequest{
		ID: "7", Method: "POST", URL: "https://app.internal/api", ResourceType: "XHR", BodySize: 12,
		Headers: map[string]string{"Authorization": "Bearer t", "X-API-Key": "k", "Accept": "*/*"},
	}})
	rec.event(Event{Type: EventHTTPResponse, Response: &HTTPResponse{
		ID: "7", Status: 201, StatusText: "Created", MimeType: "application/json", BodySize: 2,
		Headers: map[string]string{"Set-Cookie": "sid=1", "Content-Type": "application/json"},
	}})
	rec.event(Event{Type: EventBlockedRequest, Method: "GET", URL: "https://other.internal/"})
	rec.event(Event{Type: EventDialog, DialogType: "confirm", Text: "Leave?"})
	rec.event(Event{Type: EventDialogClosed, DialogType: "confirm", Text: "Leave?", Accepted: true})
	x, y := 10.0, 20.0
	rec.input("click", &x, &y, `"Sign in" button`, "")
	rec.input("key", nil, nil, `"Password" field`, recordedText("s", Element{Masked: true}, true))
	rec.event(Event{Type: EventEnded, Text: EndUserQuit})
	rec.event(Event{Type: EventNavigation, URL: "https://app.internal/after-the-end"})

	envelopes := logger.envelopes(t)
	var types []string
	for _, envelope := range envelopes {
		types = append(types, envelope["type"].(string))
		require.GreaterOrEqual(t, envelope["elapsedMs"].(float64), float64(prior.Milliseconds()), "a reconnect continues the earlier recording's clock")
	}
	require.Equal(t, []string{
		"session_start", "frame", "navigation", "http_request", "http_response",
		"blocked_request", "dialog", "input", "input", "session_end",
	}, types)

	require.Equal(t, "https://app.internal/", envelopes[0]["url"])
	require.Equal(t, float64(1280), envelopes[0]["width"])
	jpegBytes, err := base64.StdEncoding.DecodeString(envelopes[1]["jpeg"].(string))
	require.NoError(t, err)
	require.Equal(t, white, jpegBytes)
	require.Equal(t, float64(1), envelopes[1]["seq"])
	require.Equal(t, "Home", envelopes[2]["title"])
	require.Equal(t, map[string]any{"Authorization": maskedText, "X-API-Key": maskedText, "Accept": "*/*"}, envelopes[3]["headers"],
		"credential headers, the account's custom one included, are kept by name only")
	require.Equal(t, "POST", envelopes[3]["method"])
	require.Equal(t, map[string]any{"Set-Cookie": maskedText, "Content-Type": "application/json"}, envelopes[4]["headers"])
	require.Equal(t, float64(201), envelopes[4]["status"])
	require.Equal(t, "GET", envelopes[5]["method"])
	require.Equal(t, map[string]any{"type": "dialog", "elapsedMs": envelopes[6]["elapsedMs"], "kind": "confirm", "message": "Leave?", "accepted": true}, envelopes[6])
	require.Equal(t, `"Sign in" button`, envelopes[7]["target"])
	require.Equal(t, float64(10), envelopes[7]["x"])
	require.Equal(t, maskedText, envelopes[8]["text"])
	require.Equal(t, EndUserQuit, envelopes[9]["reason"])

	logger.mu.Lock()
	defer logger.mu.Unlock()
	for i := 1; i < len(logger.events); i++ {
		require.GreaterOrEqual(t, logger.events[i].ElapsedTime, logger.events[i-1].ElapsedTime)
	}
}

func TestRecorderThrottlesAndDedupesFrames(t *testing.T) {
	logger := &recordingLogger{}
	rec := newRecorder(BrowserProxyConfig{SessionID: "frames-test", SessionLogger: logger})
	white, black := testJPEG(t, color.White), testJPEG(t, color.Black)

	rec.frame(Frame{JPEG: white})
	rec.frame(Frame{JPEG: white})
	rec.frame(Frame{JPEG: black})
	require.Eventually(t, func() bool { return len(logger.ofType(t, "frame")) == 2 }, time.Second, 10*time.Millisecond)
	frames := logger.ofType(t, "frame")
	last, err := base64.StdEncoding.DecodeString(frames[1]["jpeg"].(string))
	require.NoError(t, err)
	require.Equal(t, black, last)

	rec.frame(Frame{JPEG: black})
	time.Sleep(3 * recordedFrameInterval)
	require.Len(t, logger.ofType(t, "frame"), 2)

	rec.end(EndUserQuit)
	require.Len(t, logger.ofType(t, "session_end"), 1)
}

func TestFitJPEGReencodesFramesTooBigToRecord(t *testing.T) {
	// Noise makes a big JPEG.
	noisy := image.NewRGBA(image.Rect(0, 0, 400, 300))
	random := rand.New(rand.NewSource(1))
	for i := range noisy.Pix {
		noisy.Pix[i] = uint8(random.Intn(256))
	}
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, noisy, &jpeg.Options{Quality: 100}))

	limit := buf.Len() / 2
	fitted, ok := fitJPEG(buf.Bytes(), limit)
	require.True(t, ok)
	require.LessOrEqual(t, len(fitted), limit)
	_, err := jpeg.Decode(bytes.NewReader(fitted))
	require.NoError(t, err)

	_, ok = fitJPEG(buf.Bytes(), 100)
	require.False(t, ok, "a frame that can't be made small enough isn't recorded")
}

func TestRecordedTextIsMaskedWhereItMustBe(t *testing.T) {
	require.Equal(t, "hello", recordedText("hello", Element{Label: `"Search" field`}, true))
	require.Equal(t, maskedText, recordedText("hunter2", Element{Masked: true}, true))
	require.Equal(t, maskedText, recordedText("hunter2", Element{}, false), "a field that couldn't be identified might be a password field")
	require.Equal(t, "", recordedText("", Element{Masked: true}, true), "keys that type nothing stay textless")

	long := recordedText(strings.Repeat("é", maxRecordedTextLength), Element{}, true)
	require.True(t, utf8.ValidString(long))
	require.LessOrEqual(t, len(long), maxRecordedTextLength)
}
