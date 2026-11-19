package webapp

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type memLogger struct {
	mu     sync.Mutex
	events []session.WebEvent
}

func (l *memLogger) LogWebEvent(ev session.WebEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	return nil
}

func (l *memLogger) all() []session.WebEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]session.WebEvent(nil), l.events...)
}

func feed(r *recorder, events ...any) {
	for _, ev := range events {
		r.handle(recorderItem{at: time.Now(), cdp: ev})
	}
}

func request(id, method, url string, ts float64, typ network.ResourceType) *network.EventRequestWillBeSent {
	return &network.EventRequestWillBeSent{
		RequestID: network.RequestID(id),
		Request:   &network.Request{Method: method, URL: url},
		Timestamp: cdp.MonotonicTime(ts),
		Type:      typ,
	}
}

func httpEvents(events []session.WebEvent) []session.WebEvent {
	var out []session.WebEvent
	for _, ev := range events {
		if ev.EventType == session.WebEventHTTP {
			out = append(out, ev)
		}
	}
	return out
}

func TestRecorderFoldsRedirectChain(t *testing.T) {
	logger := &memLogger{}
	r := newRecorder(logger, "s", 16)
	redirect := request("1", "GET", "https://grafana.internal/b", 1.1, network.ResourceTypeDocument)
	redirect.RedirectResponse = &network.Response{Status: 302, MimeType: "text/html", EncodedDataLength: 120}
	feed(r,
		request("1", "GET", "https://grafana.internal/a", 1.0, network.ResourceTypeDocument),
		redirect,
		&network.EventResponseReceived{RequestID: "1", Type: network.ResourceTypeDocument, Response: &network.Response{Status: 200, MimeType: "text/html"}},
		&network.EventLoadingFinished{RequestID: "1", Timestamp: 1.35, EncodedDataLength: 4096},
	)
	got := httpEvents(logger.all())
	if len(got) != 2 {
		t.Fatalf("events = %+v", got)
	}
	want := []struct {
		url               string
		status            int
		bytes, durationMs int64
	}{
		{"https://grafana.internal/a", 302, 120, 100},
		{"https://grafana.internal/b", 200, 4096, 250},
	}
	for i, w := range want {
		ev := got[i]
		if ev.URL != w.url || ev.Status != w.status || ev.RespBytes != w.bytes || ev.DurationMs != w.durationMs ||
			ev.Method != "GET" || ev.ResourceType != "document" || ev.MimeType != "text/html" || ev.Blocked || ev.Error != "" {
			t.Errorf("hop %d = %+v %+v, want %+v", i, ev, *ev.WebRequest, w)
		}
	}
}

func TestRecorderFailedAndBlockedRequests(t *testing.T) {
	logger := &memLogger{}
	r := newRecorder(logger, "s", 16)
	feed(r,
		request("1", "POST", "https://api.internal/save", 2.0, network.ResourceTypeXHR),
		&network.EventLoadingFailed{RequestID: "1", Timestamp: 2.5, ErrorText: "net::ERR_CONNECTION_REFUSED"},
		request("2", "GET", "https://evil.example/x", 3.0, network.ResourceTypeScript),
	)
	r.handle(recorderItem{blocked: "2"})
	feed(r,
		&network.EventLoadingFailed{RequestID: "2", Timestamp: 3.0, ErrorText: "net::ERR_BLOCKED_BY_CLIENT"},
		request("3", "GET", "http://mixed.example/img", 4.0, network.ResourceTypeImage),
		&network.EventLoadingFailed{RequestID: "3", ErrorText: "net::ERR_BLOCKED_BY_CLIENT", BlockedReason: network.BlockedReasonMixedContent},
	)
	got := httpEvents(logger.all())
	if len(got) != 3 {
		t.Fatalf("events = %+v", got)
	}
	if got[0].Status != 0 || got[0].Error != "net::ERR_CONNECTION_REFUSED" || got[0].Blocked || got[0].DurationMs != 500 || got[0].ResourceType != "xhr" {
		t.Errorf("failed request = %+v", *got[0].WebRequest)
	}
	if !got[1].Blocked || got[1].ResourceType != "script" {
		t.Errorf("allowlist refusal = %+v", *got[1].WebRequest)
	}
	if !got[2].Blocked {
		t.Errorf("request with a blocked reason = %+v", *got[2].WebRequest)
	}
	if len(r.blocked) != 0 {
		t.Errorf("blocked marks left: %v", r.blocked)
	}
}

func TestRecorderWebSocket(t *testing.T) {
	logger := &memLogger{}
	r := newRecorder(logger, "s", 16)
	feed(r,
		&network.EventWebSocketCreated{RequestID: "w", URL: "wss://grafana.internal/api/live/ws"},
		&network.EventWebSocketWillSendHandshakeRequest{RequestID: "w", Timestamp: 5.0},
		&network.EventWebSocketHandshakeResponseReceived{RequestID: "w", Timestamp: 5.02, Response: &network.WebSocketResponse{Status: 101}},
		&network.EventWebSocketClosed{RequestID: "w", Timestamp: 9.0},
		&network.EventWebSocketCreated{RequestID: "v", URL: "wss://gone.internal/ws"},
		&network.EventWebSocketClosed{RequestID: "v", Timestamp: 9.0},
	)
	got := httpEvents(logger.all())
	if len(got) != 2 {
		t.Fatalf("events = %+v", got)
	}
	if got[0].Method != "GET" || got[0].ResourceType != "websocket" || got[0].Status != 101 || got[0].DurationMs != 20 || got[0].Error != "" {
		t.Errorf("websocket = %+v", *got[0].WebRequest)
	}
	if got[1].Status != 0 || got[1].Error == "" {
		t.Errorf("websocket closed before handshake = %+v", *got[1].WebRequest)
	}
}

func TestRecorderFlushesUnfinishedAndEndsSession(t *testing.T) {
	logger := &memLogger{}
	r := newRecorder(logger, "s", 16)
	r.start()
	r.observe(request("1", "GET", "https://grafana.internal/api/live", 1.0, network.ResourceTypeFetch))
	r.observe(&network.EventResponseReceived{RequestID: "1", Response: &network.Response{Status: 200, MimeType: "text/event-stream"}})
	r.observe(request("2", "GET", "data:image/png;base64,AAAA", 1.0, network.ResourceTypeImage))
	r.finish("viewer disconnected")

	got := logger.all()
	if len(got) != 2 {
		t.Fatalf("events = %+v", got)
	}
	if got[0].URL != "https://grafana.internal/api/live" || got[0].Error != "unfinished" || got[0].Status != 200 || got[0].ResourceType != "fetch" {
		t.Errorf("unfinished = %+v %+v", got[0], *got[0].WebRequest)
	}
	if got[1].EventType != session.WebEventSession || got[1].Action != "end" || got[1].Detail != "viewer disconnected" {
		t.Errorf("end = %+v", got[1])
	}
}

func TestRecorderNavigationAndSessionEvents(t *testing.T) {
	logger := &memLogger{}
	r := newRecorder(logger, "s", 16)
	feed(r,
		&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "main", URL: "about:blank"}},
		&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "main", URL: "https://grafana.internal/d/1", URLFragment: "#panel"}},
		&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "child", ParentID: "main", URL: "https://grafana.internal/frame"}},
		&page.EventNavigatedWithinDocument{FrameID: "main", URL: "https://grafana.internal/d/2"},
		&page.EventNavigatedWithinDocument{FrameID: "child", URL: "https://grafana.internal/frame#x"},
		&page.EventWindowOpen{URL: "https://grafana.internal/popup?token=abc"},
		&page.EventJavascriptDialogOpening{Type: page.DialogTypeConfirm, Message: "Delete the dashboard named secret?"},
		&page.EventFileChooserOpened{},
		&browser.EventDownloadWillBegin{URL: "https://grafana.internal/export?id=7"},
	)
	got := logger.all()
	want := []session.WebEvent{
		{EventType: session.WebEventNavigation, URL: "https://grafana.internal/d/1#panel"},
		{EventType: session.WebEventNavigation, URL: "https://grafana.internal/d/2"},
		{EventType: session.WebEventSession, Action: "popup", Detail: "https://grafana.internal/popup?token=***"},
		{EventType: session.WebEventSession, Action: "dialog", Detail: "confirm"},
		{EventType: session.WebEventSession, Action: "upload.blocked"},
		{EventType: session.WebEventSession, Action: "download.blocked", Detail: "https://grafana.internal/export?id=***"},
	}
	if len(got) != len(want) {
		t.Fatalf("events = %+v", got)
	}
	for i := range want {
		got[i].Timestamp = time.Time{}
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRecorderQueueIsBounded(t *testing.T) {
	logger := &memLogger{}
	r := newRecorder(logger, "s", 4)
	done := make(chan struct{})
	go func() {
		for range 10 {
			r.logSession("popup", "")
		}
		r.observe(&page.EventFileChooserOpened{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a full queue blocked the producer")
	}
	r.start()
	r.finish("browser closed")

	got := logger.all()
	if len(got) != 6 {
		t.Fatalf("got %d events, want 4 queued plus dropped and end: %+v", len(got), got)
	}
	if got[4].Action != "recording.dropped" || got[4].Detail != "7 events" {
		t.Errorf("dropped = %+v", got[4])
	}
	if got[5].Action != "end" {
		t.Errorf("last = %+v", got[5])
	}
}

func TestRecorderIgnoresUnrecordedEvents(t *testing.T) {
	r := newRecorder(&memLogger{}, "s", 4)
	r.observe(&page.EventScreencastFrame{})
	r.observe(&page.EventLoadEventFired{})
	r.observe(&network.EventDataReceived{})
	if len(r.queue) != 0 {
		t.Fatalf("queued %d events that are never recorded", len(r.queue))
	}
}

func TestRecorderInputTargets(t *testing.T) {
	logger := &memLogger{}
	r := newRecorder(logger, "s", 16)

	resolved := make(chan *session.WebTarget, 1)
	resolved <- &session.WebTarget{Tag: "a", Role: "link", Name: "Save", Text: "Save"}
	r.logInput(session.WebEvent{EventType: session.WebEventInput, Action: "click", X: 5, Y: 6}, resolved, false)

	slow := make(chan *session.WebTarget)
	r.logInput(session.WebEvent{EventType: session.WebEventInput, Action: "click", X: 7, Y: 8}, slow, false)
	r.logInput(session.WebEvent{EventType: session.WebEventInput, Action: "submit"}, slow, true)

	start := time.Now()
	for n := len(r.queue); n > 0; n-- {
		r.handle(<-r.queue)
	}
	if elapsed := time.Since(start); elapsed > 3*targetTimeout {
		t.Errorf("waited %v for targets", elapsed)
	}

	got := logger.all()
	if len(got) != 2 {
		t.Fatalf("events = %+v", got)
	}
	if got[0].Target == nil || got[0].Target.Tag != "a" || got[0].X != 5 {
		t.Errorf("resolved click = %+v", got[0])
	}
	if got[1].Target != nil || got[1].X != 7 || got[1].Action != "click" {
		t.Errorf("click past the timeout = %+v", got[1])
	}
}
