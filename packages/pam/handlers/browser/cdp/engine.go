package cdp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/browser"
	cdpbrowser "github.com/chromedp/cdproto/browser"
	cdpproto "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

const (
	// A page load fires request and response events for every resource at once.
	eventBufferSize   = 4096
	screencastQuality = 70
	cursorBinding     = "__infisicalCursor"
	// So one URL can't make a record too big to upload.
	maxRecordedURLLength = 8 * 1024
)

var errDialogOpen = errors.New("a dialog is open and must be answered first")

type Engine struct {
	pool *Pool
}

func NewEngine(pool *Pool) *Engine {
	return &Engine{pool: pool}
}

func (e *Engine) Start(ctx context.Context, opts browser.StartOptions) (browser.Session, error) {
	instance, err := e.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	s, err := newSession(ctx, instance, opts)
	if err != nil {
		instance.Stop()
		return nil, err
	}
	return s, nil
}

type session struct {
	instance   *Instance
	opts       browser.StartOptions
	ctx        context.Context // the tab's chromedp context
	cancel     context.CancelFunc
	frames     chan browser.Frame
	events     chan browser.Event
	screencast chan *page.EventScreencastFrame
	pumpDone   chan struct{}
	dialogOpen atomic.Bool

	mu            sync.Mutex
	stopped       bool
	targetID      target.ID
	mainFrameID   cdpproto.FrameID
	pageURL       string
	pageTitle     string
	dialogKind    string
	dialogMessage string
}

func newSession(ctx context.Context, instance *Instance, opts browser.StartOptions) (*session, error) {
	if opts.Width <= 0 || opts.Height <= 0 {
		opts.Width, opts.Height = defaultWindowWidth, defaultWindowHeight
	}
	// The tab outlives ctx, which only bounds setup, so it hangs off Background.
	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(context.Background(), instance.CDPURL, chromedp.NoModifyURL)
	tabCtx, cancelTab := chromedp.NewContext(allocCtx)
	s := &session{
		instance: instance,
		opts:     opts,
		ctx:      tabCtx,
		cancel: func() {
			cancelTab()
			cancelAlloc()
		},
		frames: make(chan browser.Frame),
		events: make(chan browser.Event, eventBufferSize),
		// Chromium sends a frame only after the previous one is acked.
		screencast: make(chan *page.EventScreencastFrame, 2),
		pumpDone:   make(chan struct{}),
	}
	// Registered before the tab exists so no paused request goes unanswered.
	chromedp.ListenTarget(tabCtx, s.onEvent)
	chromedp.ListenBrowser(tabCtx, s.onBrowserEvent)

	// A deadline on the first Run would close the tab for good, so ctx can only cancel it.
	stopSetup := context.AfterFunc(ctx, s.cancel)
	err := chromedp.Run(tabCtx, s.setupActions()...)
	stopSetup()
	if err != nil {
		s.cancel()
		return nil, fmt.Errorf("failed to set up browser tab: %w", err)
	}
	s.mu.Lock()
	s.targetID = chromedp.FromContext(tabCtx).Target.TargetID
	s.mu.Unlock()

	go s.pumpFrames()
	go func() {
		select {
		case <-instance.Done():
			s.Stop(browser.EndBrowserStopped)
		case <-tabCtx.Done():
		}
	}()
	return s, nil
}

func (s *session) setupActions() []chromedp.Action {
	actions := []chromedp.Action{
		emulation.SetDeviceMetricsOverride(int64(s.opts.Width), int64(s.opts.Height), 1, false),
		chromedp.ActionFunc(dropHeadlessUserAgent),
		fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: "*"}}),
		runtime.AddBinding(cursorBinding),
		addScript(cursorScript),
	}
	if !s.opts.AllowDownloads {
		actions = append(actions, onBrowser(cdpbrowser.SetDownloadBehavior(cdpbrowser.SetDownloadBehaviorBehaviorDeny).Do))
	}
	if s.opts.IgnoreTLSErrors {
		actions = append(actions, onBrowser(security.SetIgnoreCertificateErrors(true).Do))
	}
	if script := hideSelectorsScript(s.opts.HiddenSelectors); script != "" {
		actions = append(actions, addScript(script))
	}
	return append(actions, page.StartScreencast().
		WithFormat(page.ScreencastFormatJpeg).
		WithQuality(screencastQuality).
		WithMaxWidth(browser.MaxFrameWidth).
		WithMaxHeight(browser.MaxFrameHeight))
}

func (s *session) onEvent(ev any) {
	switch e := ev.(type) {
	case *fetch.EventRequestPaused:
		// Answering the pause is a CDP call, which a listener mustn't make inline.
		go s.handlePausedRequest(e)
	case *page.EventScreencastFrame:
		select {
		case s.screencast <- e:
		default:
			// An unacked frame would stall the screencast.
			go s.ackFrame(e.SessionID)
		}
	case *page.EventFrameNavigated:
		if e.Frame.ParentID == "" {
			s.mu.Lock()
			s.mainFrameID = e.Frame.ID
			s.mu.Unlock()
			// A new document's title comes later.
			noTitle := ""
			s.setPage(e.Frame.URL, &noTitle)
		}
	case *page.EventNavigatedWithinDocument:
		// History API and hash changes.
		s.mu.Lock()
		isMainFrame := e.FrameID == s.mainFrameID
		s.mu.Unlock()
		if isMainFrame {
			s.setPage(e.URL, nil)
		}
	case *page.EventJavascriptDialogOpening:
		s.mu.Lock()
		s.dialogKind, s.dialogMessage = string(e.Type), e.Message
		s.mu.Unlock()
		s.dialogOpen.Store(true)
		s.emit(browser.Event{
			Type:          browser.EventDialog,
			URL:           e.URL,
			Text:          e.Message,
			DialogType:    string(e.Type),
			DefaultPrompt: e.DefaultPrompt,
		})
	case *page.EventJavascriptDialogClosed:
		s.dialogOpen.Store(false)
		s.mu.Lock()
		kind, message := s.dialogKind, s.dialogMessage
		s.mu.Unlock()
		s.emit(browser.Event{Type: browser.EventDialogClosed, DialogType: kind, Text: message, Accepted: e.Result})
	case *network.EventRequestWillBeSent:
		s.onRequest(e)
	case *network.EventResponseReceived:
		s.emitResponse(string(e.RequestID), e.Response)
	case *network.EventLoadingFailed:
		// Blocked requests are reported as such, and cancelled ones were never answered.
		if e.Canceled || e.ErrorText == "net::ERR_BLOCKED_BY_CLIENT" {
			return
		}
		s.emit(browser.Event{Type: browser.EventHTTPResponse, Response: &browser.HTTPResponse{ID: string(e.RequestID), StatusText: e.ErrorText}})
	case *network.EventWebSocketCreated:
		// The Fetch domain never sees WebSocket handshakes, so this is the only trace of them.
		if recordableURL(e.URL) {
			s.emit(browser.Event{Type: browser.EventHTTPRequest, Request: &browser.HTTPRequest{
				ID: string(e.RequestID), Method: "GET", URL: truncateURL(e.URL), ResourceType: "WebSocket",
			}})
		}
	case *runtime.EventBindingCalled:
		if e.Name == cursorBinding {
			s.emit(browser.Event{Type: browser.EventCursor, Text: safeCursor(e.Payload)})
		}
	}
}

// The page domain has no title event.
func (s *session) onBrowserEvent(ev any) {
	e, ok := ev.(*target.EventTargetInfoChanged)
	if !ok || e.TargetInfo == nil {
		return
	}
	s.mu.Lock()
	ours := s.targetID != "" && e.TargetInfo.TargetID == s.targetID
	s.mu.Unlock()
	if ours {
		s.setPage(e.TargetInfo.URL, &e.TargetInfo.Title)
	}
}

// A nil title keeps the current one.
func (s *session) setPage(url string, title *string) {
	// about:blank and Chromium's error page aren't places the user went.
	if !recordableURL(url) {
		return
	}
	s.mu.Lock()
	changed := url != s.pageURL || (title != nil && *title != s.pageTitle)
	s.pageURL = url
	if title != nil {
		s.pageTitle = *title
	}
	event := browser.Event{Type: browser.EventNavigation, URL: s.pageURL, Title: s.pageTitle}
	s.mu.Unlock()
	if changed {
		s.emit(event)
	}
}

func (s *session) handlePausedRequest(e *fetch.EventRequestPaused) {
	ctx := cdpproto.WithExecutor(s.ctx, chromedp.FromContext(s.ctx).Target)
	requestURL := e.Request.URL

	if !browser.RequestAllowed(requestURL, s.opts.AllowedHost) {
		s.emit(browser.Event{Type: browser.EventBlockedRequest, URL: truncateURL(requestURL), Method: e.Request.Method})
		if err := fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ctx); err != nil {
			log.Debug().Err(err).Str("sessionID", s.opts.SessionID).Msg("Failed to block browser request")
		}
		return
	}

	continueRequest := fetch.ContinueRequest(e.RequestID)
	if len(s.opts.CredentialHeaders) > 0 && browser.Origin(requestURL) == s.opts.CredentialOrigin {
		continueRequest = continueRequest.WithHeaders(withCredentialHeaders(e.Request.Headers, s.opts.CredentialHeaders))
	}
	if err := continueRequest.Do(ctx); err != nil {
		log.Debug().Err(err).Str("sessionID", s.opts.SessionID).Msg("Failed to continue browser request")
	}
}

func (s *session) onRequest(e *network.EventRequestWillBeSent) {
	if e.Request == nil {
		return
	}
	// A redirect keeps the request id; the redirect response answers the previous hop.
	if e.RedirectResponse != nil {
		s.emitResponse(string(e.RequestID), e.RedirectResponse)
	}
	// Blocked requests are reported by the Fetch handler instead.
	if !recordableURL(e.Request.URL) || !browser.RequestAllowed(e.Request.URL, s.opts.AllowedHost) {
		return
	}
	headers := headerStrings(e.Request.Headers)
	s.emit(browser.Event{Type: browser.EventHTTPRequest, Request: &browser.HTTPRequest{
		ID:           string(e.RequestID),
		Method:       e.Request.Method,
		URL:          truncateURL(e.Request.URL),
		Headers:      headers,
		ResourceType: string(e.Type),
		BodySize:     contentLength(headers),
	}})
}

func (s *session) emitResponse(requestID string, response *network.Response) {
	if response == nil || !recordableURL(response.URL) {
		return
	}
	headers := headerStrings(response.Headers)
	s.emit(browser.Event{Type: browser.EventHTTPResponse, Response: &browser.HTTPResponse{
		ID:         requestID,
		Status:     int(response.Status),
		StatusText: response.StatusText,
		Headers:    headers,
		MimeType:   response.MimeType,
		BodySize:   contentLength(headers),
		FromCache:  response.FromDiskCache || response.FromPrefetchCache || response.FromServiceWorker,
	}})
}

func (s *session) ElementAt(ctx context.Context, x, y float64) (browser.Element, error) {
	return s.describe(ctx, fmt.Sprintf(describeElementScript, true, x, y))
}

func (s *session) FocusedElement(ctx context.Context) (browser.Element, error) {
	return s.describe(ctx, fmt.Sprintf(describeElementScript, false, 0.0, 0.0))
}

func (s *session) describe(ctx context.Context, script string) (browser.Element, error) {
	// Evaluation stalls behind an open dialog just as input does.
	if s.dialogOpen.Load() {
		return browser.Element{}, errDialogOpen
	}
	var result struct {
		Label  string `json:"label"`
		Masked bool   `json:"masked"`
	}
	if err := s.run(ctx, chromedp.Evaluate(script, &result)); err != nil {
		return browser.Element{}, err
	}
	return browser.Element{Label: result.Label, Masked: result.Masked}, nil
}

// A frame is acked only once the reader takes it, so Chromium produces frames no faster than
// the viewer receives them.
func (s *session) pumpFrames() {
	defer close(s.pumpDone)
	for {
		select {
		case <-s.ctx.Done():
			return
		case e := <-s.screencast:
			if frame, ok := decodeFrame(e); ok {
				select {
				case s.frames <- frame:
				case <-s.ctx.Done():
					return
				}
			}
			s.ackFrame(e.SessionID)
		}
	}
}

func (s *session) ackFrame(frameSessionID int64) {
	ctx := cdpproto.WithExecutor(s.ctx, chromedp.FromContext(s.ctx).Target)
	if err := page.ScreencastFrameAck(frameSessionID).Do(ctx); err != nil && s.ctx.Err() == nil {
		log.Debug().Err(err).Str("sessionID", s.opts.SessionID).Msg("Failed to ack screencast frame")
	}
}

// Never blocks: callers are the CDP listener and request handlers.
func (s *session) emit(event browser.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	select {
	case s.events <- event:
	default:
		log.Warn().Str("sessionID", s.opts.SessionID).Str("type", string(event.Type)).Msg("Browser event buffer full, dropping event")
	}
}

func (s *session) Navigate(ctx context.Context, rawURL string) error {
	return s.run(ctx, chromedp.Navigate(rawURL))
}

func (s *session) Resize(ctx context.Context, width, height int) error {
	return s.run(ctx, emulation.SetDeviceMetricsOverride(int64(width), int64(height), 1, false))
}

func (s *session) Input(ctx context.Context, in browser.Input) error {
	// Input dispatch blocks while a dialog is up, so don't queue any behind it.
	if s.dialogOpen.Load() {
		return errDialogOpen
	}
	modifiers := input.Modifier(in.Modifiers)
	var action chromedp.Action
	switch in.Type {
	case browser.InputMouse:
		var mouseType input.MouseType
		switch in.Action {
		case "down":
			mouseType = input.MousePressed
		case "up":
			mouseType = input.MouseReleased
		case "move":
			mouseType = input.MouseMoved
		default:
			return fmt.Errorf("unknown mouse action %q", in.Action)
		}
		action = input.DispatchMouseEvent(mouseType, in.X, in.Y).
			WithButton(mouseButton(in.Button)).
			WithButtons(int64(in.Buttons)).
			WithClickCount(int64(in.Clicks)).
			WithModifiers(modifiers)
	case browser.InputWheel:
		action = input.DispatchMouseEvent(input.MouseWheel, in.X, in.Y).
			WithDeltaX(in.DeltaX).
			WithDeltaY(in.DeltaY).
			WithModifiers(modifiers)
	case browser.InputKey:
		keyType := input.KeyUp
		if in.Action == "down" {
			// Keys that type something are keyDown with text; Chromium needs the rest raw.
			keyType = input.KeyRawDown
			if in.Text != "" {
				keyType = input.KeyDown
			}
		}
		action = input.DispatchKeyEvent(keyType).
			WithKey(in.Key).
			WithCode(in.Code).
			WithText(in.Text).
			WithWindowsVirtualKeyCode(int64(in.KeyCode)).
			WithModifiers(modifiers)
	case browser.InputText:
		action = input.InsertText(in.Text)
	default:
		return fmt.Errorf("unknown input type %q", in.Type)
	}
	return s.run(ctx, action)
}

func (s *session) HandleDialog(ctx context.Context, accept bool, promptText string) error {
	return s.run(ctx, page.HandleJavaScriptDialog(accept).WithPromptText(promptText))
}

func (s *session) Frames() <-chan browser.Frame {
	return s.frames
}

func (s *session) Events() <-chan browser.Event {
	return s.events
}

func (s *session) Stop(reason string) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	// Last, so the handler can tell the viewer why.
	select {
	case s.events <- browser.Event{Type: browser.EventEnded, Text: reason}:
	default:
	}
	close(s.events)
	s.mu.Unlock()

	s.cancel()
	<-s.pumpDone
	close(s.frames)
	s.instance.Stop()
	log.Info().Str("sessionID", s.opts.SessionID).Str("reason", reason).Msg("Browser session stopped")
}

// Abandons the actions, not the tab, if ctx ends first.
func (s *session) run(ctx context.Context, actions ...chromedp.Action) error {
	runCtx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	return chromedp.Run(runCtx, actions...)
}

func onBrowser(do func(context.Context) error) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		return do(cdpproto.WithExecutor(ctx, chromedp.FromContext(ctx).Browser))
	})
}

func addScript(source string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(source).Do(ctx)
		return err
	})
}

// The headless shell's user agent says HeadlessChrome, which some apps refuse to serve.
func dropHeadlessUserAgent(ctx context.Context) error {
	_, _, _, userAgent, _, err := cdpbrowser.GetVersion().Do(cdpproto.WithExecutor(ctx, chromedp.FromContext(ctx).Browser))
	if err != nil {
		return err
	}
	return emulation.SetUserAgentOverride(strings.Replace(userAgent, "HeadlessChrome", "Chrome", 1)).Do(ctx)
}

func decodeFrame(e *page.EventScreencastFrame) (browser.Frame, bool) {
	jpeg, err := base64.StdEncoding.DecodeString(e.Data)
	if err != nil || e.Metadata == nil {
		return browser.Frame{}, false
	}
	return browser.Frame{
		JPEG:      jpeg,
		Width:     int(math.Round(e.Metadata.DeviceWidth)),
		Height:    int(math.Round(e.Metadata.DeviceHeight)),
		Timestamp: time.Now(),
	}, true
}

func mouseButton(button string) input.MouseButton {
	switch button {
	case "left":
		return input.Left
	case "middle":
		return input.Middle
	case "right":
		return input.Right
	}
	return input.None
}

// Overriding headers replaces all of them, so the originals are carried over.
func withCredentialHeaders(original network.Headers, credential map[string]string) []*fetch.HeaderEntry {
	entries := make([]*fetch.HeaderEntry, 0, len(original)+len(credential))
	for name, value := range original {
		if !hasHeader(credential, name) {
			entries = append(entries, &fetch.HeaderEntry{Name: name, Value: fmt.Sprint(value)})
		}
	}
	for name, value := range credential {
		entries = append(entries, &fetch.HeaderEntry{Name: name, Value: value})
	}
	return entries
}

// data: and blob: URLs never leave the browser, and a data: URI can be megabytes.
func recordableURL(rawURL string) bool {
	for _, scheme := range []string{"http:", "https:", "ws:", "wss:"} {
		if len(rawURL) >= len(scheme) && strings.EqualFold(rawURL[:len(scheme)], scheme) {
			return true
		}
	}
	return false
}

func truncateURL(rawURL string) string {
	if len(rawURL) > maxRecordedURLLength {
		return rawURL[:maxRecordedURLLength]
	}
	return rawURL
}

func headerStrings(headers network.Headers) map[string]string {
	result := make(map[string]string, len(headers))
	for name, value := range headers {
		result[name] = fmt.Sprint(value)
	}
	return result
}

func contentLength(headers map[string]string) int {
	for name, value := range headers {
		if strings.EqualFold(name, "Content-Length") {
			length, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil && length > 0 {
				return length
			}
		}
	}
	return 0
}

// A frame it can't see into is masked, as it could hold a password field. Never reads values.
const describeElementScript = `((point, x, y) => {
	let el = point ? document.elementFromPoint(x, y) : document.activeElement;
	for (let depth = 0; el && depth < 10; depth++) {
		if (!point && el.shadowRoot && el.shadowRoot.activeElement) { el = el.shadowRoot.activeElement; continue; }
		if (el.tagName === "IFRAME" || el.tagName === "FRAME") {
			let inner = null;
			try { inner = point ? null : el.contentDocument && el.contentDocument.activeElement; } catch (e) {}
			if (!inner) return { label: "embedded frame", masked: true };
			el = inner;
			continue;
		}
		break;
	}
	if (!el || el === document.body || el === document.documentElement) return { label: "", masked: false };
	const tag = el.tagName.toLowerCase();
	const type = (el.getAttribute("type") || "").toLowerCase();
	const role = el.getAttribute("role");
	const isButtonInput = tag === "input" && ["button", "submit", "reset"].includes(type);
	let kind = "";
	if (tag === "button" || role === "button" || isButtonInput) kind = "button";
	else if (tag === "a" || role === "link") kind = "link";
	else if (tag === "input" || tag === "textarea" || tag === "select" || el.isContentEditable) kind = "field";
	let text = el.getAttribute("aria-label") || el.getAttribute("placeholder") || el.getAttribute("title") ||
		el.getAttribute("name") || el.getAttribute("alt") || "";
	if (!text && isButtonInput) text = el.getAttribute("value") || "";
	if (!text && kind !== "field" && el.childElementCount < 10) text = el.innerText || "";
	text = text.replace(/\s+/g, " ").trim().slice(0, 60);
	const masked = tag === "input" && type === "password";
	if (!text) return { label: kind, masked };
	return { label: kind ? "\"" + text + "\" " + kind : "\"" + text + "\"", masked };
})(%t, %f, %f)`

func hasHeader(headers map[string]string, name string) bool {
	for candidate := range headers {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
}

// CDP has no cursor event.
const cursorScript = `(() => {
	let last = "";
	addEventListener("mousemove", (event) => {
		const target = event.target instanceof Element ? event.target : document.documentElement;
		const cursor = getComputedStyle(target).cursor;
		if (cursor !== last && typeof globalThis.` + cursorBinding + ` === "function") {
			last = cursor;
			globalThis.` + cursorBinding + `(cursor);
		}
	}, { capture: true, passive: true });
})();`

var cursorKeywords = map[string]bool{
	"auto": true, "default": true, "none": true, "context-menu": true, "help": true, "pointer": true,
	"progress": true, "wait": true, "cell": true, "crosshair": true, "text": true, "vertical-text": true,
	"alias": true, "copy": true, "move": true, "no-drop": true, "not-allowed": true, "grab": true,
	"grabbing": true, "all-scroll": true, "col-resize": true, "row-resize": true, "n-resize": true,
	"e-resize": true, "s-resize": true, "w-resize": true, "ne-resize": true, "nw-resize": true,
	"se-resize": true, "sw-resize": true, "ew-resize": true, "ns-resize": true, "nesw-resize": true,
	"nwse-resize": true, "zoom-in": true, "zoom-out": true,
}

// Any page script can call the binding and the viewer applies the value as CSS, so only
// keywords get through.
func safeCursor(value string) string {
	parts := strings.Split(value, ",")
	keyword := strings.TrimSpace(parts[len(parts)-1])
	if cursorKeywords[keyword] {
		return keyword
	}
	return "default"
}

// An adopted stylesheet applies before the DOM exists.
func hideSelectorsScript(selectors []string) string {
	var rules []string
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		// A brace would let one entry close its rule and start another.
		if selector == "" || strings.ContainsAny(selector, "{}") {
			continue
		}
		rules = append(rules, selector+" { visibility: hidden !important; }")
	}
	if len(rules) == 0 {
		return ""
	}
	css, _ := json.Marshal(strings.Join(rules, "\n"))
	return fmt.Sprintf(`(() => {
	const sheet = new CSSStyleSheet();
	sheet.replaceSync(%s);
	document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
})();`, css)
}
