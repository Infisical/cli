package browser

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeSession struct {
	frames chan Frame
	events chan Event

	mu            sync.Mutex
	inputs        []Input
	resizes       [][2]int
	dialogReplies []bool
	focused       Element
	stopReason    string
	stopOnce      sync.Once
}

func newFakeSession() *fakeSession {
	return &fakeSession{frames: make(chan Frame), events: make(chan Event, 8)}
}

func (f *fakeSession) Navigate(ctx context.Context, url string) error { return nil }

func (f *fakeSession) Resize(ctx context.Context, width, height int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resizes = append(f.resizes, [2]int{width, height})
	return nil
}

func (f *fakeSession) Input(ctx context.Context, input Input) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inputs = append(f.inputs, input)
	return nil
}

func (f *fakeSession) HandleDialog(ctx context.Context, accept bool, promptText string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialogReplies = append(f.dialogReplies, accept)
	return nil
}

func (f *fakeSession) ElementAt(ctx context.Context, x, y float64) (Element, error) {
	return Element{Label: `"Sign in" button`}, nil
}

func (f *fakeSession) FocusedElement(ctx context.Context) (Element, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.focused, nil
}

func (f *fakeSession) Frames() <-chan Frame { return f.frames }

func (f *fakeSession) Events() <-chan Event { return f.events }

func (f *fakeSession) Stop(reason string) {
	f.stopOnce.Do(func() {
		f.mu.Lock()
		f.stopReason = reason
		f.mu.Unlock()
		f.events <- Event{Type: EventEnded, Text: reason}
		close(f.events)
		close(f.frames)
	})
}

type fakeEngine struct {
	session *fakeSession
	err     error
}

func (e fakeEngine) Start(ctx context.Context, opts StartOptions) (Session, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.session, nil
}

func readServerMessage(t *testing.T, conn net.Conn) ServerMessage {
	t.Helper()
	messageType, payload, err := ReadMessage(conn, 1<<20)
	require.NoError(t, err)
	require.Equal(t, MessageJSON, messageType)
	var message ServerMessage
	require.NoError(t, json.Unmarshal(payload, &message))
	return message
}

func startProxy(t *testing.T, config BrowserProxyConfig) (net.Conn, <-chan error) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- NewBrowserProxy(config).HandleConnection(t.Context(), server) }()
	return client, done
}

func TestBrowserProxyRelaysFramesInputDialogsAndEnd(t *testing.T) {
	fake := newFakeSession()
	var activity atomic.Int32
	client, done := startProxy(t, BrowserProxyConfig{
		SessionID:  "relay-test",
		TargetURL:  "http://app.internal",
		Engine:     fakeEngine{session: fake},
		OnActivity: func() { activity.Add(1) },
	})

	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientResize, Width: 1920, Height: 1080}))
	require.Equal(t, ServerMessage{Type: ServerReady, URL: "http://app.internal", Width: 1920, Height: 1080}, readServerMessage(t, client),
		"ready comes first, carrying the viewport the browser uses")

	fake.frames <- Frame{JPEG: []byte("jpeg"), Width: 1920, Height: 1080, Timestamp: time.Now()}
	messageType, payload, err := ReadMessage(client, 1<<20)
	require.NoError(t, err)
	require.Equal(t, MessageFrame, messageType)
	header, jpeg, err := DecodeFrame(payload)
	require.NoError(t, err)
	require.Equal(t, uint32(1), header.Seq)
	require.Equal(t, [2]uint16{1920, 1080}, [2]uint16{header.Width, header.Height})
	require.Equal(t, []byte("jpeg"), jpeg)

	fake.events <- Event{Type: EventDialog, Text: "Leave?", DialogType: "confirm"}
	require.Equal(t, ServerMessage{Type: ServerDialog, ID: 1, Kind: "confirm", Message: "Leave?"}, readServerMessage(t, client))
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientDialogReply, DialogID: 7, Accept: false}))
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientDialogReply, DialogID: 1, Accept: true}))
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientDialogReply, DialogID: 1, Accept: false}))

	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientMouse, Action: "down", X: 10, Y: 20, Button: "left", Buttons: 1, ClickCount: 1}))
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientResize, Width: 5000, Height: 5000}))
	require.Eventually(t, func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return len(fake.inputs) == 1 && len(fake.resizes) == 1
	}, time.Second, 10*time.Millisecond)
	fake.mu.Lock()
	require.Equal(t, []bool{true}, fake.dialogReplies)
	require.Equal(t, Input{Type: InputMouse, Action: "down", X: 10, Y: 20, Button: "left", Buttons: 1, Clicks: 1}, fake.inputs[0])
	require.Equal(t, [2]int{maxViewportWidth, maxViewportHeight}, fake.resizes[0], "resizes are capped at the viewer's own limit")
	fake.mu.Unlock()

	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientEnd}))
	require.Equal(t, ServerMessage{Type: ServerEnd, Reason: EndUserQuit}, readServerMessage(t, client))
	require.NoError(t, <-done)
	require.Equal(t, EndUserQuit, fake.stopReason)
	// The opening resize isn't activity.
	require.Equal(t, int32(6), activity.Load())
}

func TestBrowserProxyRecordsTheSessionWithoutTypedPasswords(t *testing.T) {
	fake := newFakeSession()
	fake.focused = Element{Label: `"Password" field`, Masked: true}
	logger := &recordingLogger{}
	client, done := startProxy(t, BrowserProxyConfig{
		SessionID:     "record-test",
		TargetURL:     "http://app.internal",
		Engine:        fakeEngine{session: fake},
		SessionLogger: logger,
	})

	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientResize, Width: 1280, Height: 800}))
	require.Equal(t, ServerReady, readServerMessage(t, client).Type)
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientMouse, Action: "down", X: 5, Y: 6, Button: "left", Buttons: 1, ClickCount: 1}))
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientMouse, Action: "up", X: 5, Y: 6, Button: "left", ClickCount: 1}))
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientKey, Action: "down", Key: "h", Code: "KeyH", KeyCode: 72, Text: "h"}))
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientKey, Action: "up", Key: "h", Code: "KeyH", KeyCode: 72}))
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientEnd}))
	require.Equal(t, ServerEnd, readServerMessage(t, client).Type)
	require.NoError(t, <-done)

	var types []string
	for _, envelope := range logger.envelopes(t) {
		types = append(types, envelope["type"].(string))
	}
	require.Equal(t, []string{"session_start", "input", "input", "session_end"}, types)
	inputs := logger.ofType(t, "input")
	require.Equal(t, "click", inputs[0]["kind"])
	require.Equal(t, `"Sign in" button`, inputs[0]["target"])
	require.Equal(t, "key", inputs[1]["kind"])
	require.Equal(t, `"Password" field`, inputs[1]["target"])
	require.Equal(t, maskedText, inputs[1]["text"])
	require.Equal(t, EndUserQuit, logger.ofType(t, "session_end")[0]["reason"])
}

func TestBrowserProxyReportsCapacity(t *testing.T) {
	client, done := startProxy(t, BrowserProxyConfig{
		SessionID: "capacity-test",
		TargetURL: "http://app.internal",
		Engine:    fakeEngine{err: ErrAtCapacity},
	})
	require.NoError(t, writeJSON(client, ClientMessage{Type: ClientResize, Width: 1280, Height: 800}))
	require.Equal(t, ServerMessage{Type: ServerEnd, Reason: EndCapacity}, readServerMessage(t, client))
	require.ErrorIs(t, <-done, ErrAtCapacity)
}

func TestBrowserProxyWithoutEngineTellsTheViewer(t *testing.T) {
	client, done := startProxy(t, BrowserProxyConfig{SessionID: "no-engine"})

	message := readServerMessage(t, client)
	require.Equal(t, ServerEnd, message.Type)
	require.Equal(t, EndError, message.Reason)
	require.Contains(t, message.Message, "can't run web app sessions")
	require.Error(t, <-done)
}
