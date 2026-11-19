package webapp

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/rs/zerolog/log"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

const (
	recorderQueueSize = 4096
	maxOpenRequests   = 4096
	targetTimeout     = 200 * time.Millisecond
)

// WebEventLogger is where a web app session writes its activity log.
type WebEventLogger interface {
	LogWebEvent(event session.WebEvent) error
}

type recorderItem struct {
	at time.Time

	cdp any

	event *session.WebEvent
	// target delivers the input event's target. With requireTarget, an event whose target
	// never arrives is not logged.
	target        <-chan *session.WebTarget
	requireTarget bool

	blocked network.RequestID
}

type openRequest struct {
	at           time.Time
	method       string
	url          string
	resourceType string
	start        cdp.MonotonicTime
	status       int64
	mimeType     string
}

type screenshotSink interface {
	trigger(name string)
	network(inFlight int)
}

// recorder turns browser events and viewer input into the session's activity log. It writes
// on its own goroutine, so a slow disk never holds up the browser's message loop.
type recorder struct {
	logger    WebEventLogger
	sessionID string
	queue     chan recorderItem
	dropped   atomic.Int64
	stop      chan struct{}
	done      chan struct{}
	endDetail string

	// screens hears about every logged trigger and every change in requests in flight.
	screens      screenshotSink
	lastInFlight int

	open      map[network.RequestID]*openRequest
	blocked   map[network.RequestID]bool
	mainFrame cdp.FrameID
}

func newRecorder(logger WebEventLogger, sessionID string, queueSize int) *recorder {
	return &recorder{
		logger:    logger,
		sessionID: sessionID,
		queue:     make(chan recorderItem, queueSize),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		open:      make(map[network.RequestID]*openRequest),
		blocked:   make(map[network.RequestID]bool),
	}
}

func (r *recorder) start() {
	go r.run()
}

// finish writes what is still pending and the end of the session, then returns once the log is
// complete. Events that arrive later are not recorded.
func (r *recorder) finish(detail string) {
	r.endDetail = detail
	close(r.stop)
	<-r.done
}

func (r *recorder) enqueue(item recorderItem) {
	item.at = time.Now()
	select {
	case r.queue <- item:
	default:
		r.dropped.Add(1)
	}
}

// observe takes every browser event. It runs on the browser's message loop and never blocks.
func (r *recorder) observe(ev any) {
	switch ev.(type) {
	case *network.EventRequestWillBeSent, *network.EventResponseReceived,
		*network.EventLoadingFinished, *network.EventLoadingFailed,
		*network.EventWebSocketCreated, *network.EventWebSocketWillSendHandshakeRequest,
		*network.EventWebSocketHandshakeResponseReceived, *network.EventWebSocketClosed,
		*page.EventFrameNavigated, *page.EventNavigatedWithinDocument,
		*page.EventWindowOpen, *page.EventJavascriptDialogOpening,
		*page.EventFileChooserOpened, *browser.EventDownloadWillBegin:
		r.enqueue(recorderItem{cdp: ev})
	}
}

func (r *recorder) log(event session.WebEvent) {
	r.enqueue(recorderItem{event: &event})
}

func (r *recorder) logSession(action, detail string) {
	r.log(session.WebEvent{EventType: session.WebEventSession, Action: action, Detail: detail})
}

func (r *recorder) logInput(event session.WebEvent, target <-chan *session.WebTarget, requireTarget bool) {
	r.enqueue(recorderItem{event: &event, target: target, requireTarget: requireTarget})
}

// markBlocked records that the allowlist refused a request, so its failure is logged as blocked.
func (r *recorder) markBlocked(id network.RequestID) {
	if id != "" {
		r.enqueue(recorderItem{blocked: id})
	}
}

func (r *recorder) run() {
	defer close(r.done)
	for {
		select {
		case item := <-r.queue:
			r.handle(item)
		case <-r.stop:
			// Only what is queued now, since a live browser can keep adding events.
			for n := len(r.queue); n > 0; n-- {
				r.handle(<-r.queue)
			}
			r.flush()
			return
		}
	}
}

func (r *recorder) flush() {
	open := make([]*openRequest, 0, len(r.open))
	for _, req := range r.open {
		open = append(open, req)
	}
	slices.SortFunc(open, func(a, b *openRequest) int { return a.at.Compare(b.at) })
	now := time.Now()
	for _, req := range open {
		r.writeRequest(now, req, 0, 0, "unfinished", false)
	}
	r.open = make(map[network.RequestID]*openRequest)

	if n := r.dropped.Load(); n > 0 {
		r.write(now, session.WebEvent{EventType: session.WebEventSession, Action: "recording.dropped", Detail: fmt.Sprintf("%d events", n)})
	}
	r.write(now, session.WebEvent{EventType: session.WebEventSession, Action: "end", Detail: r.endDetail})
}

func (r *recorder) write(at time.Time, event session.WebEvent) {
	event.Timestamp = at
	if err := r.logger.LogWebEvent(event); err != nil {
		log.Warn().Err(err).Str("sessionId", r.sessionID).Msg("Failed to record web app event")
	}
	if r.screens == nil {
		return
	}
	switch {
	case event.EventType == session.WebEventInput && inputTriggers[event.Action]:
		r.screens.trigger(event.Action)
	case event.EventType == session.WebEventNavigation:
		r.screens.trigger(triggerNavigation)
	}
}

func (r *recorder) handle(item recorderItem) {
	switch {
	case item.blocked != "":
		r.blocked[item.blocked] = true
	case item.event != nil:
		r.handleEvent(item)
	case item.cdp != nil:
		r.handleCDP(item.at, item.cdp)
		if r.screens != nil && len(r.open) != r.lastInFlight {
			r.lastInFlight = len(r.open)
			r.screens.network(r.lastInFlight)
		}
	}
}

func (r *recorder) handleEvent(item recorderItem) {
	event := *item.event
	if item.target != nil {
		wait := time.Until(item.at.Add(targetTimeout))
		select {
		case target := <-item.target:
			event.Target = target
		case <-time.After(max(wait, 0)):
		}
		if item.requireTarget && event.Target == nil {
			return
		}
	}
	r.write(item.at, event)
}

func (r *recorder) handleCDP(at time.Time, ev any) {
	switch ev := ev.(type) {
	case *network.EventRequestWillBeSent:
		if ev.Request == nil {
			return
		}
		if prev, ok := r.open[ev.RequestID]; ok && ev.RedirectResponse != nil {
			prev.status = ev.RedirectResponse.Status
			prev.mimeType = ev.RedirectResponse.MimeType
			r.writeRequest(at, prev, int64(ev.RedirectResponse.EncodedDataLength), ev.Timestamp, "", false)
			delete(r.open, ev.RequestID)
		}
		if !recordedScheme(ev.Request.URL) {
			return
		}
		if len(r.open) >= maxOpenRequests {
			r.dropped.Add(1)
			return
		}
		r.open[ev.RequestID] = &openRequest{
			at:           at,
			method:       ev.Request.Method,
			url:          ev.Request.URL,
			resourceType: strings.ToLower(string(ev.Type)),
			start:        ev.Timestamp,
		}
	case *network.EventResponseReceived:
		if req, ok := r.open[ev.RequestID]; ok && ev.Response != nil {
			req.status = ev.Response.Status
			req.mimeType = ev.Response.MimeType
			if ev.Type != "" {
				req.resourceType = strings.ToLower(string(ev.Type))
			}
		}
	case *network.EventLoadingFinished:
		r.finishRequest(at, ev.RequestID, int64(ev.EncodedDataLength), ev.Timestamp, "", false)
	case *network.EventLoadingFailed:
		blocked := r.blocked[ev.RequestID] || ev.BlockedReason != ""
		r.finishRequest(at, ev.RequestID, 0, ev.Timestamp, ev.ErrorText, blocked)
	case *network.EventWebSocketCreated:
		if recordedScheme(ev.URL) && len(r.open) < maxOpenRequests {
			r.open[ev.RequestID] = &openRequest{at: at, method: "GET", url: ev.URL, resourceType: "websocket"}
		}
	case *network.EventWebSocketWillSendHandshakeRequest:
		if req, ok := r.open[ev.RequestID]; ok {
			req.start = ev.Timestamp
		}
	case *network.EventWebSocketHandshakeResponseReceived:
		if req, ok := r.open[ev.RequestID]; ok && ev.Response != nil {
			req.status = ev.Response.Status
		}
		r.finishRequest(at, ev.RequestID, 0, ev.Timestamp, "", false)
	case *network.EventWebSocketClosed:
		r.finishRequest(at, ev.RequestID, 0, ev.Timestamp, "closed before the handshake completed", false)
	case *page.EventFrameNavigated:
		if ev.Frame != nil && ev.Frame.ParentID == "" {
			r.mainFrame = ev.Frame.ID
			if ev.Frame.URL != "about:blank" {
				r.write(at, session.WebEvent{EventType: session.WebEventNavigation, URL: ev.Frame.URL + ev.Frame.URLFragment})
			}
		}
	case *page.EventNavigatedWithinDocument:
		if ev.FrameID == r.mainFrame {
			r.write(at, session.WebEvent{EventType: session.WebEventNavigation, URL: ev.URL})
		}
	case *page.EventWindowOpen:
		r.write(at, session.WebEvent{EventType: session.WebEventSession, Action: "popup", Detail: session.MaskURL(ev.URL)})
	case *page.EventJavascriptDialogOpening:
		r.write(at, session.WebEvent{EventType: session.WebEventSession, Action: "dialog", Detail: string(ev.Type)})
	case *page.EventFileChooserOpened:
		r.write(at, session.WebEvent{EventType: session.WebEventSession, Action: "upload.blocked"})
	case *browser.EventDownloadWillBegin:
		r.write(at, session.WebEvent{EventType: session.WebEventSession, Action: "download.blocked", Detail: session.MaskURL(ev.URL)})
	}
}

func (r *recorder) finishRequest(at time.Time, id network.RequestID, respBytes int64, end cdp.MonotonicTime, errorText string, blocked bool) {
	delete(r.blocked, id)
	req, ok := r.open[id]
	if !ok {
		return
	}
	delete(r.open, id)
	r.writeRequest(at, req, respBytes, end, errorText, blocked)
}

func (r *recorder) writeRequest(at time.Time, req *openRequest, respBytes int64, end cdp.MonotonicTime, errorText string, blocked bool) {
	var durationMs int64
	if req.start > 0 && end > req.start {
		durationMs = int64(math.Round(float64(end-req.start) * 1000))
	}
	r.write(at, session.WebEvent{
		EventType: session.WebEventHTTP,
		URL:       req.url,
		WebRequest: &session.WebRequest{
			Method:       req.method,
			Status:       int(req.status),
			MimeType:     req.mimeType,
			ResourceType: req.resourceType,
			RespBytes:    respBytes,
			DurationMs:   durationMs,
			Blocked:      blocked,
			Error:        errorText,
		},
	})
}

// recordedScheme leaves out data: and blob: URLs, which can be megabytes long and are not requests.
func recordedScheme(rawURL string) bool {
	scheme, _, ok := strings.Cut(rawURL, ":")
	if !ok {
		return false
	}
	switch strings.ToLower(scheme) {
	case "http", "https", "ws", "wss":
		return true
	}
	return false
}
