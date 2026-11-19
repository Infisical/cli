package webapp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

const (
	defaultViewportWidth  = 1280
	defaultViewportHeight = 800

	screencastQuality = 70
	frameQueueSize    = 4
	inputQueueSize    = 64
	inputRate         = 200
	finalWriteTimeout = 2 * time.Second
	maxDialogMessage  = 200
	statePollInterval = time.Second
)

var (
	errBrowserLost  = errors.New("browser connection lost")
	errViewerClosed = errors.New("viewer connection closed")
)

type WebAppProxyConfig struct {
	SessionID     string
	StartURL      string
	AllowedHosts  []string
	SessionLogger session.SessionLogger
	// OnActivity is called for every frame the viewer sends, so only user input keeps the session alive.
	OnActivity func()
}

type WebAppProxy struct {
	config   WebAppProxyConfig
	resolver resolver
}

func NewWebAppProxy(config WebAppProxyConfig) *WebAppProxy {
	return &WebAppProxy{config: config, resolver: net.DefaultResolver}
}

// HandleConnection runs one browser for the viewer on conn until either side goes away or ctx ends.
// It returns only after the browser has exited and its profile is removed.
func (p *WebAppProxy) HandleConnection(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	out := newFrameWriter(conn)
	fail := func(message string, err error) error {
		_ = conn.SetWriteDeadline(time.Now().Add(finalWriteTimeout))
		_ = out.writeJSON(newError(message))
		return err
	}

	list, err := newAllowlist(p.config.StartURL, p.config.AllowedHosts, allowLoopbackFromEnv(), p.resolver)
	if err != nil {
		return fail("The account's start URL is not valid.", err)
	}
	if reason := list.check(ctx, p.config.StartURL); reason != nil {
		return fail("The start URL is blocked. "+reason.message, fmt.Errorf("start URL blocked: %w", reason))
	}
	execPath := FindBrowserPath()
	if execPath == "" {
		return fail("This gateway has no browser for web app sessions.", errors.New("no browser binary found"))
	}
	noSandbox, err := sandboxDisabled(os.Geteuid(), os.Getenv(browserNoSandboxEnv))
	if err != nil {
		return fail("This gateway is not set up to run web app sessions.", err)
	}
	release, ok := browserSessions.acquire(maxBrowserSessions(os.Getenv(browserMaxSessionsEnv)))
	if !ok {
		return fail("This gateway is running as many browser sessions as it allows. Try again later.", errors.New("browser session limit reached"))
	}
	defer release()

	s := &browserSession{
		sessionID:  p.config.SessionID,
		startURL:   p.config.StartURL,
		allowlist:  list,
		conn:       conn,
		out:        out,
		onActivity: p.config.OnActivity,
		events:     newEventQueue(),
		frames:     make(chan *page.EventScreencastFrame, frameQueueSize),
		width:      defaultViewportWidth,
		height:     defaultViewportHeight,
	}
	b, err := launchBrowser(ctx, browserConfig{
		execPath:          execPath,
		noSandbox:         noSandbox,
		hostResolverRules: list.hostResolverRules(),
		width:             s.width,
		height:            s.height,
		listener:          s.onTabEvent,
		browserListener:   s.events.push,
	})
	if err != nil {
		return fail("The gateway could not start a browser.", err)
	}
	defer b.close()

	return s.run(ctx, b)
}

type browserSession struct {
	sessionID  string
	startURL   string
	allowlist  *allowlist
	conn       net.Conn
	out        *frameWriter
	onActivity func()

	events *eventQueue
	frames chan *page.EventScreencastFrame
	end    context.CancelCauseFunc
	wg     sync.WaitGroup

	tab      *chromedp.Target
	browser  *chromedp.Browser
	targetID target.ID

	// width and height belong to the input goroutine once the session runs.
	width, height int64

	// lastState belongs to the event goroutine.
	lastState stateMessage
}

// isMainFrame relies on Chromium giving a tab's main frame the id of the tab's target.
func (s *browserSession) isMainFrame(id cdp.FrameID) bool {
	return string(id) == string(s.targetID)
}

type droppedFrame struct {
	sessionID int64
}

// onTabEvent runs on the tab's message loop, so it must never block or send a command.
func (s *browserSession) onTabEvent(ev any) {
	if frame, ok := ev.(*page.EventScreencastFrame); ok {
		select {
		case s.frames <- frame:
		default:
			s.events.push(droppedFrame{sessionID: frame.SessionID})
		}
		return
	}
	s.events.push(ev)
}

func (s *browserSession) run(parent context.Context, b *browserInstance) error {
	c := chromedp.FromContext(b.ctx)
	s.tab, s.browser, s.targetID = c.Target, c.Browser, c.Target.TargetID

	ctx, end := context.WithCancelCause(parent)
	s.end = end
	defer end(nil)

	if err := s.configure(ctx); err != nil {
		s.finalError("The gateway could not set up the browser.")
		return err
	}

	inputs := make(chan clientMessage, inputQueueSize)
	s.wg.Go(func() { s.processEvents(ctx) })
	s.wg.Go(func() { s.streamFrames(ctx) })
	s.wg.Go(func() { end(s.readInput(ctx, inputs)) })
	s.wg.Go(func() { s.applyInput(ctx, inputs) })

	s.send(newReady(s.width, s.height))
	s.wg.Go(func() {
		if _, err := cdp.Call(ctx, s.tab, page.Navigate, page.NavigateParams{URL: s.startURL}); err != nil && ctx.Err() == nil {
			log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Web app start navigation failed")
		}
	})

	detached, err := chromedp.Detached(b.ctx)
	if err != nil {
		end(err)
	}
	select {
	case <-ctx.Done():
	case <-b.ctx.Done():
		end(errBrowserLost)
	case <-detached:
		end(errBrowserLost)
	}

	cause := context.Cause(ctx)
	switch {
	case parent.Err() != nil:
	case errors.Is(cause, errBrowserLost):
		s.finalError("The browser stopped unexpectedly.")
	case errors.Is(cause, errInvalidFrame):
		s.finalError("The viewer sent a message the gateway could not read.")
	}
	s.conn.Close()
	s.wg.Wait()

	if errors.Is(cause, errViewerClosed) || parent.Err() != nil {
		return nil
	}
	return cause
}

func (s *browserSession) configure(ctx context.Context) error {
	if _, err := cdp.Call(ctx, s.tab, network.Enable, network.EnableParams{}); err != nil {
		return fmt.Errorf("enable network: %w", err)
	}
	if _, err := cdp.Call(ctx, s.tab, page.Enable, page.EnableParams{}); err != nil {
		return fmt.Errorf("enable page: %w", err)
	}
	if _, err := cdp.Call(ctx, s.tab, fetch.Enable, fetch.EnableParams{
		Patterns: []*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}},
	}); err != nil {
		return fmt.Errorf("enable request interception: %w", err)
	}
	if _, err := cdp.Call(ctx, s.tab, page.SetInterceptFileChooserDialog, page.SetInterceptFileChooserDialogParams{Enabled: true}); err != nil {
		return fmt.Errorf("intercept file chooser: %w", err)
	}
	eventsEnabled := true
	if _, err := cdp.Call(ctx, s.browser, browser.SetDownloadBehavior, browser.SetDownloadBehaviorParams{
		Behavior:      browser.SetDownloadBehaviorBehaviorDeny,
		EventsEnabled: &eventsEnabled,
	}); err != nil {
		return fmt.Errorf("deny downloads: %w", err)
	}
	if err := s.setViewport(ctx); err != nil {
		return err
	}
	return s.startScreencast(ctx)
}

func (s *browserSession) setViewport(ctx context.Context) error {
	if _, err := cdp.Call(ctx, s.tab, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{
		Width:             s.width,
		Height:            s.height,
		DeviceScaleFactor: 1,
	}); err != nil {
		return fmt.Errorf("set viewport: %w", err)
	}
	return nil
}

func (s *browserSession) startScreencast(ctx context.Context) error {
	quality := int64(screencastQuality)
	if _, err := cdp.Call(ctx, s.tab, page.StartScreencast, page.StartScreencastParams{
		Format:        page.StartScreencastFormatJpeg,
		Quality:       &quality,
		MaxWidth:      maxViewportSide,
		MaxHeight:     maxViewportSide,
		EveryNthFrame: 1,
	}); err != nil {
		return fmt.Errorf("start screencast: %w", err)
	}
	return nil
}

func (s *browserSession) send(msg any) {
	if err := s.out.writeJSON(msg); err != nil {
		s.end(fmt.Errorf("write to viewer: %w", err))
	}
}

// finalError tells the viewer why the session ends, without waiting long on a viewer that stopped reading.
func (s *browserSession) finalError(message string) {
	_ = s.conn.SetWriteDeadline(time.Now().Add(finalWriteTimeout))
	_ = s.out.writeJSON(newError(message))
}

func (s *browserSession) streamFrames(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-s.frames:
			if err := s.out.writeJPEG(frame.Data); err != nil {
				s.end(fmt.Errorf("write to viewer: %w", err))
				return
			}
			s.ackFrame(ctx, frame.SessionID)
		}
	}
}

func (s *browserSession) ackFrame(ctx context.Context, frameID int64) {
	if _, err := cdp.Call(ctx, s.tab, page.ScreencastFrameAck, page.ScreencastFrameAckParams{SessionID: frameID}); err != nil && ctx.Err() == nil {
		log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Failed to acknowledge screencast frame")
	}
}

func (s *browserSession) readInput(ctx context.Context, inputs chan<- clientMessage) error {
	r := bufio.NewReader(s.conn)
	limiter := rate.NewLimiter(inputRate, inputRate)
	for {
		payload, err := readClientFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return errViewerClosed
			}
			return err
		}
		if s.onActivity != nil {
			s.onActivity()
		}
		if !limiter.Allow() {
			continue
		}
		msg, err := parseClientMessage(payload)
		if err != nil {
			log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Dropping unreadable web app viewer message")
			continue
		}
		select {
		case inputs <- msg:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

func (s *browserSession) applyInput(ctx context.Context, inputs <-chan clientMessage) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-inputs:
			if err := s.apply(ctx, msg); err != nil && ctx.Err() == nil {
				log.Debug().Err(err).Str("sessionId", s.sessionID).Str("type", msg.Type).Msg("Dropping web app viewer message")
			}
		}
	}
}

func (s *browserSession) apply(ctx context.Context, msg clientMessage) error {
	switch msg.Type {
	case "mouse":
		params, err := msg.mouseParams(s.width, s.height)
		if err != nil {
			return err
		}
		_, err = cdp.Call(ctx, s.tab, input.DispatchMouseEvent, params)
		return err
	case "key":
		params, err := msg.keyParams()
		if err != nil {
			return err
		}
		_, err = cdp.Call(ctx, s.tab, input.DispatchKeyEvent, params)
		return err
	case "text":
		text, err := msg.pasteText()
		if err != nil {
			return err
		}
		_, err = cdp.Call(ctx, s.tab, input.InsertText, input.InsertTextParams{Text: text})
		return err
	case "resize":
		return s.resize(ctx, msg)
	case "navigate":
		return s.navigate(ctx, msg)
	case "back":
		return s.goHistory(ctx, -1)
	case "forward":
		return s.goHistory(ctx, 1)
	case "reload":
		_, err := cdp.Call(ctx, s.tab, page.Reload, page.ReloadParams{})
		return err
	}
	return nil
}

func (s *browserSession) resize(ctx context.Context, msg clientMessage) error {
	width, height := msg.viewport()
	if width == s.width && height == s.height {
		return nil
	}
	s.width, s.height = width, height
	if err := s.setViewport(ctx); err != nil {
		return err
	}
	// The screencast keeps the old frame size until it restarts.
	if _, err := cdp.Call(ctx, s.tab, page.StopScreencast, cdp.Empty{}); err != nil {
		return fmt.Errorf("stop screencast: %w", err)
	}
	return s.startScreencast(ctx)
}

func (s *browserSession) navigate(ctx context.Context, msg clientMessage) error {
	dest, err := msg.navigateURL()
	if err != nil {
		var reason *blockReason
		if errors.As(err, &reason) {
			s.send(newBlocked(msg.URL, reason.message))
			return nil
		}
		return err
	}
	if reason := s.allowlist.check(ctx, dest); reason != nil {
		s.send(newBlocked(dest, reason.message))
		return nil
	}
	_, err = cdp.Call(ctx, s.tab, page.Navigate, page.NavigateParams{URL: dest})
	return err
}

func (s *browserSession) goHistory(ctx context.Context, offset int64) error {
	history, err := cdp.Call(ctx, s.tab, page.GetNavigationHistory, cdp.Empty{})
	if err != nil {
		return err
	}
	i := history.CurrentIndex + offset
	if i < firstHistoryEntry(history.Entries) || i >= int64(len(history.Entries)) {
		return nil
	}
	_, err = cdp.Call(ctx, s.tab, page.NavigateToHistoryEntry, page.NavigateToHistoryEntryParams{EntryID: history.Entries[i].ID})
	return err
}

func (s *browserSession) processEvents(ctx context.Context) {
	// Chromium sends no event when a script changes the title, so the state is also polled.
	poll := time.NewTicker(statePollInterval)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			s.publishState(ctx)
		case <-s.events.ready:
			for _, ev := range s.events.drain() {
				s.handleEvent(ctx, ev)
			}
		}
	}
}

// handleEvent must not wait on a command that a paused request blocks, such as Page.navigate,
// because the request is only released by a later event in the same queue.
func (s *browserSession) handleEvent(ctx context.Context, ev any) {
	switch ev := ev.(type) {
	case droppedFrame:
		s.ackFrame(ctx, ev.sessionID)
	case *fetch.EventRequestPaused:
		s.wg.Go(func() { s.filterRequest(ctx, ev) })
	case *page.EventFrameNavigated:
		if s.isMainFrame(ev.Frame.ID) {
			s.publishState(ctx)
		}
	case *page.EventNavigatedWithinDocument:
		if s.isMainFrame(ev.FrameID) {
			s.publishState(ctx)
		}
	case *page.EventLoadEventFired:
		s.publishState(ctx)
	case *page.EventWindowOpen:
		s.wg.Go(func() { s.openPopup(ctx, ev.URL) })
	case *page.EventJavascriptDialogOpening:
		s.closeDialog(ctx, ev)
	case *page.EventFileChooserOpened:
		s.send(newNotice("File uploads are blocked in web app sessions."))
	case *browser.EventDownloadWillBegin:
		s.send(newNotice("Downloads are blocked in web app sessions."))
	}
}

func (s *browserSession) filterRequest(ctx context.Context, ev *fetch.EventRequestPaused) {
	if ev.Request == nil {
		return
	}
	if reason := s.allowlist.check(ctx, ev.Request.URL); reason != nil {
		errorReason := network.ErrorReasonBlockedByClient
		// An aborted main-frame navigation leaves the current page in place, where any other
		// failure commits an error page that takes over the tab and its history.
		if ev.ResourceType == network.ResourceTypeDocument && s.isMainFrame(ev.FrameID) {
			errorReason = network.ErrorReasonAborted
		}
		if _, err := cdp.Call(ctx, s.tab, fetch.FailRequest, fetch.FailRequestParams{
			RequestID:   ev.RequestID,
			ErrorReason: errorReason,
		}); err != nil && ctx.Err() == nil {
			log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Failed to block web app request")
		}
		if ev.ResourceType == network.ResourceTypeDocument {
			s.send(newBlocked(ev.Request.URL, reason.message))
		}
		return
	}
	if _, err := cdp.Call(ctx, s.tab, fetch.ContinueRequest, fetch.ContinueRequestParams{RequestID: ev.RequestID}); err != nil && ctx.Err() == nil {
		log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Failed to continue web app request")
	}
}

// openPopup shows a pop-up in the session's only tab, since the browser blocks new windows.
func (s *browserSession) openPopup(ctx context.Context, rawURL string) {
	if reason := s.allowlist.check(ctx, rawURL); reason != nil {
		s.send(newBlocked(rawURL, reason.message))
		return
	}
	if _, err := cdp.Call(ctx, s.tab, page.Navigate, page.NavigateParams{URL: rawURL}); err != nil && ctx.Err() == nil {
		log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Failed to open web app pop-up")
	}
}

func (s *browserSession) closeDialog(ctx context.Context, ev *page.EventJavascriptDialogOpening) {
	accept := ev.Type == page.DialogTypeAlert || ev.Type == page.DialogTypeBeforeunload
	if _, err := cdp.Call(ctx, s.tab, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: accept}); err != nil && ctx.Err() == nil {
		log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Failed to close web app dialog")
	}
	if ev.Type == page.DialogTypeBeforeunload {
		return
	}
	message := []rune(ev.Message)
	if len(message) > maxDialogMessage {
		message = append(message[:maxDialogMessage], '…')
	}
	s.send(newNotice("The page showed a dialog, which was closed automatically: " + string(message)))
}

func (s *browserSession) publishState(ctx context.Context) {
	history, err := cdp.Call(ctx, s.tab, page.GetNavigationHistory, cdp.Empty{})
	if err != nil || len(history.Entries) == 0 {
		return
	}
	i := clamp(history.CurrentIndex, 0, int64(len(history.Entries)-1))
	first := firstHistoryEntry(history.Entries)
	if i < first {
		return
	}
	entry := history.Entries[i]
	state := stateMessage{
		Type:         "state",
		URL:          entry.URL,
		Title:        entry.Title,
		CanGoBack:    i > first,
		CanGoForward: i < int64(len(history.Entries)-1),
	}
	if state == s.lastState {
		return
	}
	s.lastState = state
	s.send(state)
}

// firstHistoryEntry skips the about:blank page the tab starts on, so the viewer cannot go back to it.
func firstHistoryEntry(entries []*page.NavigationEntry) int64 {
	first := int64(0)
	for first < int64(len(entries)) && entries[first].URL == "about:blank" {
		first++
	}
	return first
}

// eventQueue hands events from the browser's message loop to the event goroutine in order.
// It has no bound, because the message loop must never block.
type eventQueue struct {
	mu    sync.Mutex
	items []any
	ready chan struct{}
}

func newEventQueue() *eventQueue {
	return &eventQueue{ready: make(chan struct{}, 1)}
}

func (q *eventQueue) push(ev any) {
	q.mu.Lock()
	q.items = append(q.items, ev)
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

func (q *eventQueue) drain() []any {
	q.mu.Lock()
	defer q.mu.Unlock()
	items := q.items
	q.items = nil
	return items
}
