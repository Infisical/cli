package webapp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/jpeg"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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

	screencastQuality = 60
	inputQueueSize    = 64
	inputRate         = 200
	finalWriteTimeout = 2 * time.Second
	maxDialogMessage  = 200
	statePollInterval = time.Second
	eventQueueSize    = 256
	firstResizeWait   = 500 * time.Millisecond
	captureFrameGrace = 500 * time.Millisecond
)

var (
	errBrowserLost  = errors.New("browser connection lost")
	errViewerClosed = errors.New("viewer connection closed")
	errViewerWrite  = errors.New("write to viewer")
	errSetupFailed  = errors.New("browser setup failed")
)

type WebAppProxyConfig struct {
	SessionID     string
	StartURL      string
	AllowedHosts  []string
	ExpiresAt     time.Time
	SessionLogger WebEventLogger
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
	sessionLog := log.With().Str("sessionId", p.config.SessionID).Logger()
	execPath := FindBrowserPath()
	if execPath == "" {
		sessionLog.Error().Msg("Refusing to start a PAM web app browser: no browser binary found")
		return fail("This gateway has no browser for web app sessions.", errors.New("no browser binary found"))
	}
	noSandbox, err := sandboxDisabled(os.Geteuid(), os.Getenv(browserNoSandboxEnv))
	if err != nil {
		sessionLog.Error().Err(err).Msg("Refusing to start a PAM web app browser")
		return fail("This gateway is not set up to run web app sessions.", err)
	}
	maxSessions := maxBrowserSessions(os.Getenv(browserMaxSessionsEnv))
	release, ok := browserSessions.acquire(maxSessions)
	if !ok {
		sessionLog.Warn().Int("activeBrowsers", browserSessions.count()).Int("maxBrowsers", maxSessions).
			Msg("Refusing to start a PAM web app browser: session limit reached")
		return fail("This gateway is running as many browser sessions as it allows. Try again later.", errors.New("browser session limit reached"))
	}
	defer release()

	sessionCtx, end := context.WithCancelCause(ctx)
	defer end(nil)
	s := &browserSession{
		sessionID:  p.config.SessionID,
		startURL:   p.config.StartURL,
		expiresAt:  p.config.ExpiresAt,
		allowlist:  list,
		conn:       conn,
		out:        out,
		onActivity: p.config.OnActivity,
		rec:        newRecorder(p.config.SessionLogger, p.config.SessionID, recorderQueueSize),
		ctx:        sessionCtx,
		end:        end,
		ready:      make(chan struct{}),
		events:     make(chan any, eventQueueSize),
		frameReady: make(chan struct{}, 1),
		width:      defaultViewportWidth,
		height:     defaultViewportHeight,
		scale:      1,
	}
	s.captureScale.Store(math.Float64bits(1))
	s.inputs = make(chan clientMessage, inputQueueSize)
	s.wg.Go(func() { end(s.readInput(sessionCtx, s.inputs)) })
	screenScale := s.awaitScreenScale(sessionCtx)
	s.screenScale = screenScale
	s.screens = newScreenshotScheduler(defaultScreenshotTiming, s.captureViewport, s.scrollPosition, s.rec.log)
	s.rec.screens = s.screens
	sessionLog.Info().
		Str("browserPath", execPath).
		Bool("sandbox", !noSandbox).
		Str("viewport", fmt.Sprintf("%dx%d", s.width, s.height)).
		Float64("screenScale", screenScale).
		Int("activeBrowsers", browserSessions.count()).
		Int("maxBrowsers", maxSessions).
		Msg("Starting PAM web app browser")
	launchStart := time.Now()
	b, err := launchBrowser(sessionCtx, browserConfig{
		execPath:          execPath,
		noSandbox:         noSandbox,
		hostResolverRules: list.hostResolverRules(),
		width:             s.width,
		height:            s.height,
		screenScale:       screenScale,
		listener:          s.onTabEvent,
		browserListener:   s.onTabEvent,
	})
	if err != nil {
		sessionLog.Error().Err(err).Dur("launchDuration", time.Since(launchStart)).Msg("PAM web app browser failed to start")
		return fail("The gateway could not start a browser.", err)
	}
	pid := b.pid()
	startedAt := time.Now()
	sessionLog.Info().Int("pid", pid).Dur("launchDuration", startedAt.Sub(launchStart)).Msg("PAM web app browser started")
	defer func() {
		closeStart := time.Now()
		b.close()
		release()
		sessionLog.Info().
			Int("pid", pid).
			Str("reason", s.endReason).
			Dur("lifetime", time.Since(startedAt)).
			Dur("closeDuration", time.Since(closeStart)).
			Int("activeBrowsers", browserSessions.count()).
			Msg("PAM web app browser stopped")
	}()

	return s.run(ctx, b)
}

type browserSession struct {
	sessionID  string
	startURL   string
	expiresAt  time.Time
	allowlist  *allowlist
	conn       net.Conn
	out        *frameWriter
	onActivity func()
	rec        *recorder
	screens    *screenshotScheduler

	ctx context.Context
	end context.CancelCauseFunc
	// ready is closed once the fields below it are set.
	ready chan struct{}
	wg    sync.WaitGroup

	events        chan any
	droppedEvents atomic.Int64

	// latestFrame holds the newest frame the viewer has not been sent yet. A newer frame replaces
	// it, so a slow viewer always gets the current picture instead of a backlog.
	frameMu     sync.Mutex
	latestFrame []byte
	frameReady  chan struct{}

	// captureScale mirrors scale as float64 bits for the screenshot goroutine.
	captureScale atomic.Uint64
	// checkFramesUntil is set while a screenshot is taken and shortly after. A capture scaled
	// below the device scale factor briefly resizes the view, and the screencast can send a frame
	// of that size to the viewer, even after the capture has returned. sentSize is the size of the
	// last frame sent, so such a frame can be told apart.
	checkFramesUntil atomic.Int64
	sentSize         atomic.Uint64

	tab       cdp.Session
	browser   cdp.Session
	targetID  target.ID
	describer *targetDescriber

	inputs chan clientMessage
	// firstInput is the message read while choosing the screen's scale factor, applied first.
	firstInput *clientMessage

	// width, height, scale and pressed belong to the input goroutine once the session runs.
	width, height int64
	scale         float64
	pressed       *pressedButton

	// screenScale is the browser's launch scale factor. It is set before the session runs.
	screenScale float64

	// lastState belongs to the event goroutine.
	lastState stateMessage

	// endReason is set once run returns.
	endReason string
}

// isMainFrame relies on Chromium giving a tab's main frame the id of the tab's target.
func (s *browserSession) isMainFrame(id cdp.FrameID) bool {
	return string(id) == string(s.targetID)
}

// onTabEvent runs on the browser's message loops, so it must never block or send a command.
// Events that the page waits on, or that would stall the screencast if lost, get their own
// goroutine instead of a place in the bounded event queue. Each one stands for a paused request,
// an open dialog or an unacknowledged frame, so there are never more than the page has in flight.
func (s *browserSession) onTabEvent(ev any) {
	s.rec.observe(ev)
	switch ev := ev.(type) {
	case *page.EventScreencastFrame:
		// Acknowledging at once lets Chromium paint the next frame while this one is still on its
		// way to the viewer.
		s.spawn(func() { s.ackFrame(s.ctx, ev.SessionID) })
		if time.Now().UnixNano() < s.checkFramesUntil.Load() && !s.matchesSentSize(ev.Data) {
			return
		}
		s.frameMu.Lock()
		s.latestFrame = ev.Data
		s.frameMu.Unlock()
		select {
		case s.frameReady <- struct{}{}:
		default:
		}
	case *fetch.EventRequestPaused:
		s.spawn(func() { s.filterRequest(s.ctx, ev) })
	case *page.EventJavascriptDialogOpening:
		s.spawn(func() { s.closeDialog(s.ctx, ev) })
	case *page.EventWindowOpen:
		s.spawn(func() { s.openPopup(s.ctx, ev.URL) })
	case *page.EventFrameNavigated, *page.EventNavigatedWithinDocument, *page.EventLoadEventFired,
		*page.EventFileChooserOpened, *browser.EventDownloadWillBegin:
		select {
		case s.events <- ev:
		default:
			s.droppedEvents.Add(1)
		}
	}
}

// spawn runs f on its own goroutine once the session knows its tab.
func (s *browserSession) spawn(f func()) {
	go func() {
		select {
		case <-s.ready:
			f()
		case <-s.ctx.Done():
		}
	}()
}

func (s *browserSession) run(parent context.Context, b *browserInstance) (err error) {
	c := chromedp.FromContext(b.ctx)
	s.tab, s.browser, s.targetID = c.Target, c.Browser, c.Target.TargetID
	s.describer = &targetDescriber{tab: s.tab, mainFrame: cdp.FrameID(s.targetID)}
	close(s.ready)

	ctx := s.ctx
	end := s.end
	s.rec.start()
	s.rec.logSession("start", session.MaskURL(s.startURL))
	s.screens.start(ctx)
	defer func() {
		cause := context.Cause(ctx)
		if err != nil {
			cause = err
		}
		s.screens.stop()
		s.endReason = endReason(cause, parent.Err(), s.expired())
		s.rec.finish(s.endReason)
		if n := s.droppedEvents.Load(); n > 0 {
			log.Debug().Int64("dropped", n).Str("sessionId", s.sessionID).Msg("Web app session dropped page events")
		}
	}()

	if err := s.configure(ctx); err != nil {
		s.finalError("The gateway could not set up the browser.")
		return fmt.Errorf("%w: %w", errSetupFailed, err)
	}

	s.wg.Go(func() { s.processEvents(ctx) })
	s.wg.Go(func() { s.streamFrames(ctx) })
	s.wg.Go(func() { s.applyInput(ctx, s.inputs) })

	s.send(newReady(s.width, s.height, s.screenScale))
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
		s.browserLost(b, "PAM web app browser stopped unexpectedly")
	case <-detached:
		s.browserLost(b, "PAM web app browser detached unexpectedly")
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

// browserLost ends the session for a browser that went away. The browser's context is a child of
// the session's, so both can be done at once when the session ends normally, and only a session
// still running lost its browser.
func (s *browserSession) browserLost(b *browserInstance, message string) {
	if s.ctx.Err() == nil {
		log.Warn().Str("sessionId", s.sessionID).Int("pid", b.pid()).Msg(message)
	}
	s.end(errBrowserLost)
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
		DeviceScaleFactor: s.scale,
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
		MaxWidth:      int64(math.Round(float64(s.width) * s.scale)),
		MaxHeight:     int64(math.Round(float64(s.height) * s.scale)),
		EveryNthFrame: 1,
	}); err != nil {
		return fmt.Errorf("start screencast: %w", err)
	}
	return nil
}

func (s *browserSession) send(msg any) {
	if err := s.out.writeJSON(msg); err != nil {
		s.end(fmt.Errorf("%w: %w", errViewerWrite, err))
	}
}

func (s *browserSession) expired() bool {
	return !s.expiresAt.IsZero() && !time.Now().Before(s.expiresAt)
}

// endReason says in plain words why the session ended, for the activity log.
func endReason(cause, parentErr error, expired bool) string {
	switch {
	case expired:
		return "session expired"
	case parentErr != nil:
		return "session terminated"
	case errors.Is(cause, errBrowserLost):
		return "browser closed"
	case errors.Is(cause, errViewerClosed), errors.Is(cause, errViewerWrite):
		return "viewer disconnected"
	case errors.Is(cause, errInvalidFrame):
		return "viewer sent an invalid message"
	case errors.Is(cause, errSetupFailed):
		return "browser could not be set up"
	}
	return "session ended unexpectedly"
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
		case <-s.frameReady:
			s.frameMu.Lock()
			frame := s.latestFrame
			s.latestFrame = nil
			s.frameMu.Unlock()
			if frame == nil {
				continue
			}
			if err := s.out.writeJPEG(frame); err != nil {
				s.end(fmt.Errorf("%w: %w", errViewerWrite, err))
				return
			}
			if size, ok := jpegSize(frame); ok {
				s.sentSize.Store(size)
			}
		}
	}
}

// awaitScreenScale waits briefly for the viewer's first message, which is normally its resize,
// because the browser's screen scale factor can only be set at launch. A resize then sets the
// starting viewport, so ready reports the size the session uses.
func (s *browserSession) awaitScreenScale(ctx context.Context) float64 {
	select {
	case msg := <-s.inputs:
		if msg.Type != "resize" {
			s.firstInput = &msg
			return 1
		}
		s.width, s.height, s.scale = msg.viewport()
		s.captureScale.Store(math.Float64bits(s.scale))
		return s.scale
	case <-time.After(firstResizeWait):
	case <-ctx.Done():
	}
	return 1
}

func (s *browserSession) matchesSentSize(frame []byte) bool {
	size, ok := jpegSize(frame)
	sent := s.sentSize.Load()
	return !ok || sent == 0 || size == sent
}

func jpegSize(frame []byte) (uint64, bool) {
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(frame))
	if err != nil {
		return 0, false
	}
	return uint64(cfg.Width)<<32 | uint64(cfg.Height), true
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
	if s.firstInput != nil {
		if err := s.apply(ctx, *s.firstInput); err != nil && ctx.Err() == nil {
			log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Dropping web app viewer message")
		}
	}
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
		if err := s.dispatchMouse(ctx, params); err != nil {
			return err
		}
		s.recordMouse(ctx, params)
		if params.Type == input.DispatchMouseEventTypeMouseWheel {
			s.screens.scrolled()
		}
		return nil
	case "key":
		params, err := msg.keyParams()
		if err != nil {
			return err
		}
		if _, err := cdp.Call(ctx, s.tab, input.DispatchKeyEvent, params); err != nil {
			return err
		}
		if params.Type != input.DispatchKeyEventTypeKeyUp {
			if params.Key == "Enter" {
				s.recordSubmit(ctx)
			}
			if scrollKeys[params.Key] {
				s.screens.scrolled()
			}
		}
		return nil
	case "text":
		text, err := msg.pasteText()
		if err != nil {
			return err
		}
		if _, err := cdp.Call(ctx, s.tab, input.InsertText, input.InsertTextParams{Text: text}); err != nil {
			return err
		}
		s.rec.log(session.WebEvent{EventType: session.WebEventInput, Action: "paste", Length: utf8.RuneCountInString(text)})
		return nil
	case "resize":
		return s.resize(ctx, msg)
	case "navigate":
		s.recordToolbar("navigate")
		return s.navigate(ctx, msg)
	case "back":
		s.recordToolbar("back")
		return s.goHistory(ctx, -1)
	case "forward":
		s.recordToolbar("forward")
		return s.goHistory(ctx, 1)
	case "reload":
		s.recordToolbar("reload")
		_, err := cdp.Call(ctx, s.tab, page.Reload, page.ReloadParams{})
		return err
	}
	return nil
}

// captureViewport takes a WebP of what the viewer sees, at most 1920 image pixels wide. The
// clip's scale multiplies the device scale factor, so both go into it.
func (s *browserSession) captureViewport(ctx context.Context, quality int64) ([]byte, error) {
	metrics, err := cdp.Call(ctx, s.tab, page.GetLayoutMetrics, cdp.Empty{})
	if err != nil {
		return nil, err
	}
	vp := metrics.CSSVisualViewport
	if vp == nil || vp.ClientWidth <= 0 || vp.ClientHeight <= 0 {
		return nil, errors.New("no visual viewport")
	}
	dsf := math.Float64frombits(s.captureScale.Load())
	s.checkFramesUntil.Store(math.MaxInt64)
	defer func() { s.checkFramesUntil.Store(time.Now().Add(captureFrameGrace).UnixNano()) }()
	res, err := cdp.Call(ctx, s.tab, page.CaptureScreenshot, page.CaptureScreenshotParams{
		Format:  page.CaptureScreenshotFormatWebp,
		Quality: &quality,
		Clip: &page.Viewport{
			X:      vp.PageX,
			Y:      vp.PageY,
			Width:  vp.ClientWidth,
			Height: vp.ClientHeight,
			Scale:  screenshotScale(vp.ClientWidth, dsf),
		},
	})
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// screenshotScale keeps a capture at most screenshotMaxWidth image pixels wide.
func screenshotScale(cssWidth, deviceScaleFactor float64) float64 {
	return min(1, screenshotMaxWidth/(cssWidth*deviceScaleFactor))
}

func (s *browserSession) scrollPosition(ctx context.Context) (scrollPosition, error) {
	metrics, err := cdp.Call(ctx, s.tab, page.GetLayoutMetrics, cdp.Empty{})
	if err != nil {
		return scrollPosition{}, err
	}
	if metrics.CSSVisualViewport == nil {
		return scrollPosition{}, errors.New("no visual viewport")
	}
	return scrollPosition{
		x: int(math.Round(metrics.CSSVisualViewport.PageX)),
		y: int(math.Round(metrics.CSSVisualViewport.PageY)),
	}, nil
}

// wheelEventParams always sends both deltas: Chromium rejects a wheel event that lacks either,
// and the generated params drop a zero delta.
type wheelEventParams struct {
	Type      input.DispatchMouseEventType `json:"type"`
	X         float64                      `json:"x"`
	Y         float64                      `json:"y"`
	Modifiers int64                        `json:"modifiers,omitzero"`
	DeltaX    float64                      `json:"deltaX"`
	DeltaY    float64                      `json:"deltaY"`
}

func (s *browserSession) dispatchMouse(ctx context.Context, params input.DispatchMouseEventParams) error {
	if params.Type != input.DispatchMouseEventTypeMouseWheel {
		_, err := cdp.Call(ctx, s.tab, input.DispatchMouseEvent, params)
		return err
	}
	return s.tab.Call(ctx, input.CommandDispatchMouseEvent, wheelEventParams{
		Type:      params.Type,
		X:         params.X,
		Y:         params.Y,
		Modifiers: params.Modifiers,
		DeltaX:    params.DeltaX,
		DeltaY:    params.DeltaY,
	}, nil)
}

func (s *browserSession) recordToolbar(action string) {
	s.rec.log(session.WebEvent{EventType: session.WebEventInput, Action: action})
}

// recordMouse logs a left click once its release has been dispatched. The target is described
// from the press, because the release can start a navigation that replaces the page, and on
// another goroutine, so describing never delays the next input.
func (s *browserSession) recordMouse(ctx context.Context, params input.DispatchMouseEventParams) {
	if params.Button != input.MouseButtonLeft {
		return
	}
	switch params.Type {
	case input.DispatchMouseEventTypeMousePressed:
		x, y := int64(params.X), int64(params.Y)
		target := make(chan *session.WebTarget, 1)
		go func() {
			describeCtx, cancel := context.WithTimeout(ctx, targetTimeout)
			defer cancel()
			target <- s.describer.at(describeCtx, x, y)
		}()
		s.pressed = &pressedButton{x: int(x), y: int(y), target: target}
	case input.DispatchMouseEventTypeMouseReleased:
		if s.pressed == nil {
			return
		}
		p := s.pressed
		s.pressed = nil
		s.rec.logInput(session.WebEvent{EventType: session.WebEventInput, Action: "click", X: p.x, Y: p.y}, p.target, false)
	}
}

type pressedButton struct {
	x, y   int
	target <-chan *session.WebTarget
}

// recordSubmit logs Enter as a submit only when the focused element takes typed text.
func (s *browserSession) recordSubmit(ctx context.Context) {
	target := make(chan *session.WebTarget, 1)
	go func() {
		describeCtx, cancel := context.WithTimeout(ctx, targetTimeout)
		defer cancel()
		if t, editable := s.describer.focused(describeCtx); editable {
			target <- t
		}
	}()
	s.rec.logInput(session.WebEvent{EventType: session.WebEventInput, Action: "submit"}, target, true)
}

func (s *browserSession) resize(ctx context.Context, msg clientMessage) error {
	width, height, scale := msg.viewport()
	// The screencast renders at the launch scale at most, and the viewer maps input by the scale it
	// was told in ready, so a resize never asks for more.
	scale = min(scale, s.screenScale)
	if width == s.width && height == s.height && scale == s.scale {
		return nil
	}
	s.width, s.height, s.scale = width, height, scale
	s.captureScale.Store(math.Float64bits(scale))
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
			s.blockNavigation(msg.URL, reason)
			return nil
		}
		return err
	}
	if reason := s.allowlist.check(ctx, dest); reason != nil {
		s.blockNavigation(dest, reason)
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
		case ev := <-s.events:
			s.handleEvent(ctx, ev)
		}
	}
}

func (s *browserSession) handleEvent(ctx context.Context, ev any) {
	switch ev := ev.(type) {
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
		s.rec.markBlocked(ev.NetworkID)
		if _, err := cdp.Call(ctx, s.tab, fetch.FailRequest, fetch.FailRequestParams{
			RequestID:   ev.RequestID,
			ErrorReason: errorReason,
		}); err != nil && ctx.Err() == nil {
			log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Failed to block web app request")
		}
		if ev.ResourceType == network.ResourceTypeDocument {
			s.blockNavigation(ev.Request.URL, reason)
		}
		return
	}
	if _, err := cdp.Call(ctx, s.tab, fetch.ContinueRequest, fetch.ContinueRequestParams{RequestID: ev.RequestID}); err != nil && ctx.Err() == nil {
		log.Debug().Err(err).Str("sessionId", s.sessionID).Msg("Failed to continue web app request")
	}
}

func (s *browserSession) blockNavigation(rawURL string, reason *blockReason) {
	s.rec.logSession("navigation.blocked", session.MaskURL(rawURL))
	s.send(newBlocked(rawURL, reason.message))
}

// openPopup shows a pop-up in the session's only tab, since the browser blocks new windows.
func (s *browserSession) openPopup(ctx context.Context, rawURL string) {
	if reason := s.allowlist.check(ctx, rawURL); reason != nil {
		s.blockNavigation(rawURL, reason)
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
