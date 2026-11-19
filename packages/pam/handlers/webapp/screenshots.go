package webapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"image/jpeg"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

const (
	maxScreenshots      = 200
	maxScreenshotBytes  = 300 << 10
	screenshotQuality   = 60
	screenshotFallback  = 40
	screenshotMaxWidth  = 1280
	screenshotSignals   = 64
	screenshotCallLimit = 5 * time.Second

	triggerNavigation = "navigation"
	triggerScroll     = "scroll"
)

var inputTriggers = map[string]bool{
	"click": true, "submit": true, "navigate": true, "back": true, "forward": true, "reload": true,
}

var scrollKeys = map[string]bool{
	"PageUp": true, "PageDown": true, " ": true, "Home": true, "End": true,
	"ArrowUp": true, "ArrowDown": true, "ArrowLeft": true, "ArrowRight": true,
}

type screenshotTiming struct {
	// settleQuiet is how long the network must be idle after a trigger, and settleMax caps the wait.
	settleQuiet, settleMax time.Duration
	minGap                 time.Duration
	scrollDebounce         time.Duration
	scrollThrottle         time.Duration
}

var defaultScreenshotTiming = screenshotTiming{
	settleQuiet:    500 * time.Millisecond,
	settleMax:      2 * time.Second,
	minGap:         time.Second,
	scrollDebounce: time.Second,
	scrollThrottle: 3 * time.Second,
}

type scrollPosition struct{ x, y int }

type signalKind int

const (
	signalTrigger signalKind = iota
	signalNetwork
	signalScroll
)

type screenshotSignal struct {
	kind     signalKind
	trigger  string
	inFlight int
	at       time.Time
}

// screenshotScheduler decides when to capture the page after the user acts. It runs on its own
// goroutine and only ever receives signals without blocking, so capturing never holds up input or
// the screencast.
type screenshotScheduler struct {
	timing   screenshotTiming
	budget   int
	capture  func(ctx context.Context, quality int64) ([]byte, error)
	position func(ctx context.Context) (scrollPosition, error)
	log      func(session.WebEvent)
	signals  chan screenshotSignal
	cancel   context.CancelFunc
	done     chan struct{}

	pending     string
	pendingAt   time.Time
	inFlight    int
	lastNetwork time.Time
	lastCapture time.Time
	lastHash    [sha256.Size]byte
	taken       int
	capped      bool

	scrolling        bool
	lastScrollSignal time.Time
	lastScrollShot   time.Time
	lastScroll       scrollPosition
}

func newScreenshotScheduler(
	timing screenshotTiming,
	capture func(ctx context.Context, quality int64) ([]byte, error),
	position func(ctx context.Context) (scrollPosition, error),
	log func(session.WebEvent),
) *screenshotScheduler {
	return &screenshotScheduler{
		timing:   timing,
		budget:   maxScreenshots,
		capture:  capture,
		position: position,
		log:      log,
		signals:  make(chan screenshotSignal, screenshotSignals),
		done:     make(chan struct{}),
	}
}

func (s *screenshotScheduler) start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go s.run(ctx)
}

// stop drops any capture still waiting and returns once the scheduler has stopped logging.
func (s *screenshotScheduler) stop() {
	if s.cancel == nil {
		return
	}
	s.cancel()
	<-s.done
}

func (s *screenshotScheduler) send(sig screenshotSignal) {
	sig.at = time.Now()
	select {
	case s.signals <- sig:
	default:
	}
}

// trigger asks for a capture once the page settles. Only call it after the event the trigger
// names has been logged, because the viewer attaches the screenshot to that event.
func (s *screenshotScheduler) trigger(name string) {
	s.send(screenshotSignal{kind: signalTrigger, trigger: name})
}

func (s *screenshotScheduler) network(inFlight int) {
	s.send(screenshotSignal{kind: signalNetwork, inFlight: inFlight})
}

func (s *screenshotScheduler) scrolled() {
	s.send(screenshotSignal{kind: signalScroll})
}

// strongerTrigger is the trigger a coalesced capture keeps: user input over a navigation over a
// scroll, and the later of two of the same rank.
func strongerTrigger(current, next string) string {
	if current == "" || triggerRank(next) >= triggerRank(current) {
		return next
	}
	return current
}

func triggerRank(trigger string) int {
	switch trigger {
	case triggerScroll:
		return 0
	case triggerNavigation:
		return 1
	}
	return 2
}

func (s *screenshotScheduler) run(ctx context.Context) {
	defer close(s.done)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		timer.Reset(max(time.Until(s.nextWake()), 0))
		select {
		case <-ctx.Done():
			return
		case sig := <-s.signals:
			s.handle(sig)
		case <-timer.C:
		}
		s.step(ctx, time.Now())
	}
}

func (s *screenshotScheduler) handle(sig screenshotSignal) {
	switch sig.kind {
	case signalTrigger:
		s.pending = strongerTrigger(s.pending, sig.trigger)
		s.pendingAt = sig.at
		if sig.trigger == triggerNavigation {
			s.lastScroll = scrollPosition{}
		}
	case signalNetwork:
		s.inFlight = sig.inFlight
		s.lastNetwork = sig.at
	case signalScroll:
		s.scrolling = true
		s.lastScrollSignal = sig.at
	}
}

func (s *screenshotScheduler) nextWake() time.Time {
	next := time.Now().Add(time.Hour)
	if s.scrolling {
		next = minTime(next, s.lastScrollSignal.Add(s.timing.scrollDebounce))
	}
	if s.pending != "" {
		next = minTime(next, s.readyAt())
	}
	return next
}

func (s *screenshotScheduler) readyAt() time.Time {
	settled := s.pendingAt.Add(s.timing.settleMax)
	if s.inFlight == 0 {
		quiet := s.pendingAt
		if s.lastNetwork.After(quiet) {
			quiet = s.lastNetwork
		}
		settled = minTime(settled, quiet.Add(s.timing.settleQuiet))
	}
	if gap := s.lastCapture.Add(s.timing.minGap); gap.After(settled) {
		return gap
	}
	return settled
}

func (s *screenshotScheduler) step(ctx context.Context, now time.Time) {
	if s.scrolling && !now.Before(s.lastScrollSignal.Add(s.timing.scrollDebounce)) {
		s.scrolling = false
		s.settleScroll(ctx, now)
	}
	if s.pending != "" && !now.Before(s.readyAt()) {
		trigger := s.pending
		s.pending = ""
		s.lastCapture = now
		s.take(ctx, trigger)
	}
}

// settleScroll logs where a finished scroll left the page, and asks for a capture unless one was
// taken for a scroll too recently. A key such as Space that moved nothing is not a scroll.
func (s *screenshotScheduler) settleScroll(ctx context.Context, now time.Time) {
	callCtx, cancel := context.WithTimeout(ctx, screenshotCallLimit)
	defer cancel()
	pos, err := s.position(callCtx)
	if err != nil || pos == s.lastScroll {
		return
	}
	s.lastScroll = pos
	s.log(session.WebEvent{
		EventType: session.WebEventInput,
		Action:    triggerScroll,
		WebScroll: &session.WebScroll{ScrollX: pos.x, ScrollY: pos.y},
	})
	if !s.lastScrollShot.IsZero() && now.Sub(s.lastScrollShot) < s.timing.scrollThrottle {
		return
	}
	s.lastScrollShot = now
	s.pending = strongerTrigger(s.pending, triggerScroll)
	s.pendingAt = now
}

func (s *screenshotScheduler) take(ctx context.Context, trigger string) {
	if s.taken >= s.budget {
		if !s.capped {
			s.capped = true
			s.logSession("screenshots.capped", "200 screenshots")
		}
		return
	}
	image, err := s.captureWithin(ctx, screenshotQuality)
	if err == nil && len(image) > maxScreenshotBytes {
		image, err = s.captureWithin(ctx, screenshotFallback)
		if err == nil && len(image) > maxScreenshotBytes {
			s.logSession("screenshot.skipped", "the screenshot was over 300 KB even at lower quality")
			return
		}
	}
	if err != nil {
		if ctx.Err() == nil {
			s.logSession("screenshot.skipped", "capturing the screenshot failed")
		}
		return
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(image))
	if err != nil {
		s.logSession("screenshot.skipped", "the screenshot was not a readable image")
		return
	}
	hash := sha256.Sum256(image)
	if hash == s.lastHash {
		return
	}
	s.lastHash = hash
	s.taken++
	s.log(session.WebEvent{
		EventType: session.WebEventScreenshot,
		WebScreenshot: &session.WebScreenshot{
			Trigger: trigger,
			Width:   cfg.Width,
			Height:  cfg.Height,
			Bytes:   len(image),
			JPEG:    image,
		},
	})
}

func (s *screenshotScheduler) captureWithin(ctx context.Context, quality int64) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, screenshotCallLimit)
	defer cancel()
	return s.capture(callCtx, quality)
}

func (s *screenshotScheduler) logSession(action, detail string) {
	s.log(session.WebEvent{EventType: session.WebEventSession, Action: action, Detail: detail})
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
