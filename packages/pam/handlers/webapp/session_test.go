package webapp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp/jsonv2"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
)

func startReader(t *testing.T) (net.Conn, chan clientMessage, *atomic.Int32, chan error) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	var activity atomic.Int32
	s := &browserSession{sessionID: "s", conn: server, onActivity: func() { activity.Add(1) }}
	inputs := make(chan clientMessage, 1024)
	done := make(chan error, 1)
	go func() { done <- s.readInput(context.Background(), inputs) }()
	return client, inputs, &activity, done
}

func waitErr(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not stop")
		return nil
	}
}

func TestReadInputRateLimitsAndCountsActivity(t *testing.T) {
	client, inputs, activity, done := startReader(t)
	var burst []byte
	for range 500 {
		burst = append(burst, clientFrame(frameTypeJSON, `{"type":"mouse","action":"move","x":1,"y":1}`)...)
	}
	if _, err := client.Write(burst); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := waitErr(t, done); !errors.Is(err, errViewerClosed) {
		t.Fatalf("err = %v, want viewer closed", err)
	}
	if n := activity.Load(); n != 500 {
		t.Errorf("activity = %d, want 500", n)
	}
	if n := len(inputs); n < inputRate || n > inputRate+50 {
		t.Errorf("accepted %d of 500 messages, want about %d", n, inputRate)
	}
}

func TestReadInputDropsUnreadableJSON(t *testing.T) {
	client, inputs, _, done := startReader(t)
	stream := append(clientFrame(frameTypeJSON, `{not json`), clientFrame(frameTypeJSON, `{"type":"whatever"}`)...)
	if _, err := client.Write(stream); err != nil {
		t.Fatal(err)
	}
	client.Close()
	waitErr(t, done)
	if len(inputs) != 1 || (<-inputs).Type != "whatever" {
		t.Error("unreadable JSON was not dropped, or a later message was lost")
	}
}

func TestReadInputEndsOnInvalidFrame(t *testing.T) {
	client, _, _, done := startReader(t)
	go client.Write(clientFrame(frameTypeJPEG, "x"))
	if err := waitErr(t, done); !errors.Is(err, errInvalidFrame) {
		t.Fatalf("err = %v, want invalid frame", err)
	}
}

type fakeTab struct {
	mu    sync.Mutex
	calls map[string]int
}

func (f *fakeTab) Call(_ context.Context, method string, _, _ any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[method]++
	return nil
}

func (f *fakeTab) Subscribe(string) (<-chan jsonv2.Value, func()) {
	return nil, func() {}
}

func (f *fakeTab) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

func TestOnTabEventNeverBlocksOrDropsWhatThePageWaitsOn(t *testing.T) {
	tab := &fakeTab{}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	list := mustAllowlist(t, "https://grafana.internal", nil, false, publicResolver())
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go io.Copy(io.Discard, client)
	s := &browserSession{
		sessionID:  "s",
		allowlist:  list,
		conn:       server,
		out:        newFrameWriter(server),
		rec:        newRecorder(&memLogger{}, "s", 8),
		ctx:        ctx,
		end:        cancel,
		ready:      make(chan struct{}),
		events:     make(chan any, 2),
		frameReady: make(chan struct{}, 1),
		tab:        tab,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 1000 {
			s.onTabEvent(&page.EventLoadEventFired{})
			s.onTabEvent(&network.EventRequestWillBeSent{RequestID: network.RequestID(strconv.Itoa(i))})
		}
		for i := range 20 {
			s.onTabEvent(&fetch.EventRequestPaused{
				RequestID: fetch.RequestID(strconv.Itoa(i)),
				Request:   &network.Request{URL: "https://grafana.internal/" + strconv.Itoa(i)},
			})
		}
		s.onTabEvent(&fetch.EventRequestPaused{RequestID: "x", Request: &network.Request{URL: "https://evil.example/"}})
		for i := range 5 {
			s.onTabEvent(&page.EventScreencastFrame{SessionID: int64(i), Data: []byte{byte(i)}})
		}
		s.onTabEvent(&page.EventJavascriptDialogOpening{Type: page.DialogTypeAlert})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onTabEvent blocked")
	}
	if got := s.droppedEvents.Load(); got != 998 {
		t.Errorf("dropped page events = %d, want 998", got)
	}
	if s.rec.dropped.Load() == 0 {
		t.Error("recorder queue did not drop past its bound")
	}
	if !bytes.Equal(s.latestFrame, []byte{4}) {
		t.Errorf("latest frame = %v, want the newest", s.latestFrame)
	}

	close(s.ready)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tab.count(fetch.CommandContinueRequest) == 20 && tab.count(fetch.CommandFailRequest) == 1 &&
			tab.count(page.CommandScreencastFrameAck) == 5 && tab.count(page.CommandHandleJavaScriptDialog) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("calls = %v, want 20 continued, 1 failed, 5 frames acked, 1 dialog closed", tab.calls)
}

func TestStreamFramesSendsOnlyTheNewestFrame(t *testing.T) {
	tab := &fakeTab{}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &browserSession{
		sessionID:  "s",
		conn:       server,
		out:        newFrameWriter(server),
		rec:        newRecorder(&memLogger{}, "s", 8),
		ctx:        ctx,
		end:        cancel,
		ready:      make(chan struct{}),
		frameReady: make(chan struct{}, 1),
		tab:        tab,
	}
	close(s.ready)
	go s.streamFrames(ctx)

	// net.Pipe blocks the first write until it is read, so frames 2 to 5 arrive while the
	// viewer is busy.
	s.onTabEvent(&page.EventScreencastFrame{SessionID: 1, Data: []byte("frame 1")})
	time.Sleep(50 * time.Millisecond)
	for i := 2; i <= 5; i++ {
		s.onTabEvent(&page.EventScreencastFrame{SessionID: int64(i), Data: []byte("frame " + strconv.Itoa(i))})
	}

	read := func() string {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		payload, err := readServerFrame(client)
		if err != nil {
			return ""
		}
		return string(payload)
	}
	if got := read(); got != "frame 1" {
		t.Fatalf("first frame = %q", got)
	}
	if got := read(); got != "frame 5" {
		t.Fatalf("second frame = %q, want the newest", got)
	}
	if got := read(); got != "" {
		t.Fatalf("an older frame was sent after the newest: %q", got)
	}
	deadline := time.Now().Add(time.Second)
	for tab.count(page.CommandScreencastFrameAck) != 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := tab.count(page.CommandScreencastFrameAck); n != 5 {
		t.Errorf("acknowledged %d frames, want all 5", n)
	}
}

func readServerFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, frameHeaderBytes)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[:4])-1)
	_, err := io.ReadFull(conn, payload)
	return payload, err
}

func TestEndReason(t *testing.T) {
	cases := []struct {
		cause     error
		parentErr error
		expired   bool
		want      string
	}{
		{errViewerClosed, nil, true, "session expired"},
		{errViewerClosed, context.Canceled, false, "session terminated"},
		{errBrowserLost, nil, false, "browser closed"},
		{errViewerClosed, nil, false, "viewer disconnected"},
		{fmt.Errorf("%w: broken pipe", errViewerWrite), nil, false, "viewer disconnected"},
		{fmt.Errorf("%w: type 1", errInvalidFrame), nil, false, "viewer sent an invalid message"},
		{fmt.Errorf("%w: enable page", errSetupFailed), nil, false, "browser could not be set up"},
		{errors.New("other"), nil, false, "session ended unexpectedly"},
	}
	for _, tc := range cases {
		if got := endReason(tc.cause, tc.parentErr, tc.expired); got != tc.want {
			t.Errorf("endReason(%v, %v, %v) = %q, want %q", tc.cause, tc.parentErr, tc.expired, got, tc.want)
		}
	}
}

type paramsTab struct {
	fakeTab
	params []byte
}

func (p *paramsTab) Call(ctx context.Context, method string, params, res any) error {
	p.params, _ = jsonv2.Marshal(params)
	return p.fakeTab.Call(ctx, method, params, res)
}

func TestWheelEventAlwaysSendsBothDeltas(t *testing.T) {
	tab := &paramsTab{}
	s := &browserSession{tab: tab}
	params, err := parse(t, `{"type":"mouse","action":"wheel","x":10,"y":20,"button":"none","deltaX":0,"deltaY":120}`).mouseParams(1280, 800)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.dispatchMouse(context.Background(), params); err != nil {
		t.Fatal(err)
	}
	want := `{"type":"mouseWheel","x":10,"y":20,"deltaX":0,"deltaY":120}`
	if string(tab.params) != want {
		t.Errorf("params = %s, want %s", tab.params, want)
	}
	if tab.count(input.CommandDispatchMouseEvent) != 1 {
		t.Errorf("calls = %v", tab.calls)
	}
}
