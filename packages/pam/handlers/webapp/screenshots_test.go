package webapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

var testTiming = screenshotTiming{
	settleQuiet:    40 * time.Millisecond,
	settleMax:      200 * time.Millisecond,
	minGap:         80 * time.Millisecond,
	scrollDebounce: 80 * time.Millisecond,
	scrollThrottle: 400 * time.Millisecond,
}

func testJPEG(t *testing.T, shade uint8, padding int) []byte {
	t.Helper()
	img := image.NewGray(image.Rect(0, 0, 32, 20))
	for i := range img.Pix {
		img.Pix[i] = shade
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return append(buf.Bytes(), make([]byte, padding)...)
}

type schedulerHarness struct {
	t        *testing.T
	s        *screenshotScheduler
	mu       sync.Mutex
	events   []session.WebEvent
	captures atomic.Int32
	shade    atomic.Int32
	position atomic.Int32
}

// newHarness captures a different image every time unless capture is given.
func newHarness(t *testing.T, capture func(ctx context.Context, quality int64) ([]byte, error)) *schedulerHarness {
	h := &schedulerHarness{t: t}
	if capture == nil {
		capture = func(context.Context, int64) ([]byte, error) {
			return testJPEG(t, uint8(h.shade.Add(40)), 0), nil
		}
	}
	counted := func(ctx context.Context, q int64) ([]byte, error) {
		h.captures.Add(1)
		return capture(ctx, q)
	}
	position := func(context.Context) (scrollPosition, error) {
		return scrollPosition{y: int(h.position.Load())}, nil
	}
	h.s = newScreenshotScheduler(testTiming, counted, position, func(ev session.WebEvent) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.events = append(h.events, ev)
	})
	h.s.start(context.Background())
	t.Cleanup(h.s.stop)
	return h
}

func (h *schedulerHarness) logged() []session.WebEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]session.WebEvent(nil), h.events...)
}

func (h *schedulerHarness) screenshots() []session.WebEvent {
	var out []session.WebEvent
	for _, ev := range h.logged() {
		if ev.EventType == session.WebEventScreenshot {
			out = append(out, ev)
		}
	}
	return out
}

func (h *schedulerHarness) settle() {
	time.Sleep(testTiming.settleMax + testTiming.minGap + 100*time.Millisecond)
}

func TestScreenshotBurstOfClicksGivesOneCapture(t *testing.T) {
	h := newHarness(t, nil)
	for range 5 {
		h.s.trigger("click")
		time.Sleep(10 * time.Millisecond)
	}
	h.settle()
	shots := h.screenshots()
	if len(shots) != 1 || shots[0].Trigger != "click" {
		t.Fatalf("screenshots = %+v", shots)
	}
	if shots[0].Width != 32 || shots[0].Height != 20 || shots[0].Bytes != len(shots[0].JPEG) {
		t.Errorf("screenshot = %d x %d, %d bytes", shots[0].Width, shots[0].Height, shots[0].Bytes)
	}
}

func TestScreenshotWaitsForTheNetwork(t *testing.T) {
	h := newHarness(t, nil)
	h.s.network(2)
	h.s.trigger("click")
	time.Sleep(testTiming.settleQuiet * 3)
	if n := h.captures.Load(); n != 0 {
		t.Fatalf("captured %d times while requests were in flight", n)
	}
	time.Sleep(testTiming.settleMax)
	if n := h.captures.Load(); n != 1 {
		t.Fatalf("captures after the cap = %d, want 1", n)
	}

	h.s.trigger("click")
	h.s.network(0)
	time.Sleep(testTiming.minGap + testTiming.settleQuiet + 60*time.Millisecond)
	if n := h.captures.Load(); n != 2 {
		t.Fatalf("captures once the network was quiet = %d, want 2", n)
	}
}

func TestScreenshotCoalescingKeepsTheStrongestTrigger(t *testing.T) {
	cases := []struct {
		triggers []string
		want     string
	}{
		{[]string{"scroll", "click", "navigation"}, "click"},
		{[]string{"click", "navigation"}, "click"},
		{[]string{"navigation", "scroll"}, "navigation"},
		{[]string{"click", "submit"}, "submit"},
		{[]string{"reload", "navigation", "back"}, "back"},
	}
	for _, tc := range cases {
		h := newHarness(t, nil)
		for _, trig := range tc.triggers {
			h.s.trigger(trig)
		}
		h.settle()
		shots := h.screenshots()
		if len(shots) != 1 || shots[0].Trigger != tc.want {
			t.Errorf("%v gave %+v, want one %q", tc.triggers, shots, tc.want)
		}
		h.s.stop()
	}
}

func TestScreenshotWheelBurstAndThrottle(t *testing.T) {
	h := newHarness(t, nil)
	burst := func(y int32) {
		for range 6 {
			h.s.scrolled()
			time.Sleep(15 * time.Millisecond)
		}
		h.position.Store(y)
		time.Sleep(testTiming.scrollDebounce + testTiming.settleQuiet + testTiming.minGap + 60*time.Millisecond)
	}

	burst(300)
	if n := len(h.screenshots()); n != 1 {
		t.Fatalf("screenshots after the first burst = %d, want 1", n)
	}
	burst(600)
	if n := len(h.screenshots()); n != 1 {
		t.Fatalf("screenshots inside the throttle = %d, want 1", n)
	}
	time.Sleep(testTiming.scrollThrottle)
	burst(900)

	var scrolls []session.WebEvent
	for _, ev := range h.logged() {
		if ev.EventType == session.WebEventInput && ev.Action == "scroll" {
			scrolls = append(scrolls, ev)
		}
	}
	if len(scrolls) != 3 {
		t.Fatalf("scroll inputs = %+v, want 3 including the throttled one", scrolls)
	}
	for i, want := range []int{300, 600, 900} {
		if scrolls[i].ScrollY != want || scrolls[i].ScrollX != 0 {
			t.Errorf("scroll %d = %+v", i, scrolls[i].WebScroll)
		}
	}
	shots := h.screenshots()
	if len(shots) != 2 || shots[0].Trigger != "scroll" || shots[1].Trigger != "scroll" {
		t.Errorf("screenshots = %+v", shots)
	}

	events := h.logged()
	for i, ev := range events {
		if ev.EventType == session.WebEventScreenshot && (i == 0 || events[i-1].Action != "scroll") {
			t.Errorf("screenshot %d does not follow its scroll input", i)
		}
	}
}

func TestScreenshotScrollThatMovesNothingIsNotLogged(t *testing.T) {
	h := newHarness(t, nil)
	h.s.scrolled()
	h.settle()
	if got := h.logged(); len(got) != 0 {
		t.Errorf("logged %+v for a scroll key that moved nothing", got)
	}
}

func TestScreenshotIdenticalImageIsSkipped(t *testing.T) {
	same := testJPEG(t, 100, 0)
	h := newHarness(t, func(context.Context, int64) ([]byte, error) { return same, nil })
	h.s.trigger("click")
	h.settle()
	h.s.trigger("click")
	h.settle()
	if n := h.captures.Load(); n != 2 {
		t.Fatalf("captures = %d, want 2", n)
	}
	if got := h.logged(); len(got) != 1 || got[0].EventType != session.WebEventScreenshot {
		t.Errorf("logged %+v, want one screenshot and nothing for the duplicate", got)
	}
}

func TestScreenshotBudget(t *testing.T) {
	h := newHarness(t, nil)
	h.s.budget = 2
	for range 4 {
		h.s.trigger("click")
		h.settle()
	}
	got := h.logged()
	if len(got) != 3 {
		t.Fatalf("logged %+v", got)
	}
	if got[0].EventType != session.WebEventScreenshot || got[1].EventType != session.WebEventScreenshot {
		t.Errorf("first two = %+v", got[:2])
	}
	if got[2].Action != "screenshots.capped" || got[2].Detail != "200 screenshots" {
		t.Errorf("cap = %+v", got[2])
	}
	if n := h.captures.Load(); n != 2 {
		t.Errorf("captured %d times past the budget", n)
	}
}

func TestScreenshotSizeLimitRetriesAtLowerQuality(t *testing.T) {
	small := testJPEG(t, 50, 200<<10)
	var qualities []int64
	var mu sync.Mutex
	h := newHarness(t, func(_ context.Context, q int64) ([]byte, error) {
		mu.Lock()
		qualities = append(qualities, q)
		mu.Unlock()
		if q == screenshotQuality {
			return testJPEG(t, 50, 400<<10), nil
		}
		return small, nil
	})
	h.s.trigger("navigation")
	h.settle()
	shots := h.screenshots()
	if len(shots) != 1 || shots[0].Bytes != len(small) {
		t.Fatalf("screenshots = %d", len(shots))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(qualities) != 2 || qualities[0] != 60 || qualities[1] != 40 {
		t.Errorf("qualities = %v", qualities)
	}
}

func TestScreenshotSkippedWhenTooLargeOrFailing(t *testing.T) {
	big := newHarness(t, func(context.Context, int64) ([]byte, error) { return testJPEG(t, 1, maxScreenshotBytes+1), nil })
	big.s.trigger("click")
	big.settle()
	got := big.logged()
	if len(got) != 1 || got[0].Action != "screenshot.skipped" || got[0].Detail != "the screenshot was over 300 KB even at lower quality" {
		t.Errorf("too large logged %+v", got)
	}
	if n := big.captures.Load(); n != 2 {
		t.Errorf("captures = %d, want the retry", n)
	}

	failing := newHarness(t, func(context.Context, int64) ([]byte, error) { return nil, errors.New("boom") })
	failing.s.trigger("click")
	failing.settle()
	got = failing.logged()
	if len(got) != 1 || got[0].Action != "screenshot.skipped" || got[0].Detail != "capturing the screenshot failed" {
		t.Errorf("failure logged %+v", got)
	}
	raw, _ := json.Marshal(got[0])
	t.Logf("skipped: %s", raw)
}

func TestScreenshotSignalsNeverBlock(t *testing.T) {
	s := newScreenshotScheduler(testTiming, nil, nil, func(session.WebEvent) {})
	done := make(chan struct{})
	go func() {
		for range screenshotSignals * 10 {
			s.trigger("click")
			s.scrolled()
			s.network(1)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a scheduler that is not running blocked its callers")
	}
}

// A screenshot at the size limit must still fit one Postgres chunk (512 KiB of plaintext).
func TestLargestScreenshotEventFitsAChunk(t *testing.T) {
	event := session.WebEvent{
		Timestamp:   time.Now(),
		EventType:   session.WebEventScreenshot,
		ChannelType: session.SessionChannelWeb,
		ElapsedTime: 12345.678,
		WebScreenshot: &session.WebScreenshot{
			Trigger: "navigation", Width: 1280, Height: 3840, Bytes: maxScreenshotBytes,
			JPEG: bytes.Repeat([]byte{0xff}, maxScreenshotBytes),
		},
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)+2 > 512<<10 {
		t.Fatalf("largest screenshot event is %d bytes, over the 512 KiB chunk cap", len(raw))
	}
	t.Logf("largest screenshot event: %d bytes of %d", len(raw)+2, 512<<10)
}

func TestRecorderTriggersScreenshotsAfterLoggingTheEvent(t *testing.T) {
	logger := &memLogger{}
	r := newRecorder(logger, "s", 16)
	sink := &recordingSink{logger: logger}
	r.screens = sink
	r.handle(recorderItem{at: time.Now(), event: &session.WebEvent{EventType: session.WebEventInput, Action: "click"}})
	r.handle(recorderItem{at: time.Now(), event: &session.WebEvent{EventType: session.WebEventInput, Action: "paste"}})
	feed(r,
		request("1", "GET", "https://grafana.internal/", 1, "Document"),
		&page.EventFrameNavigated{Frame: &cdp.Frame{ID: "main", URL: "https://grafana.internal/"}},
	)
	if len(sink.triggers) != 2 || sink.triggers[0] != "click" || sink.triggers[1] != "navigation" {
		t.Errorf("triggers = %v", sink.triggers)
	}
	if sink.loggedBefore[0] != 1 || sink.loggedBefore[1] != 3 {
		t.Errorf("events logged before each trigger = %v", sink.loggedBefore)
	}
	if len(sink.inFlight) != 1 || sink.inFlight[0] != 1 {
		t.Errorf("in flight = %v", sink.inFlight)
	}
}

type recordingSink struct {
	logger       *memLogger
	triggers     []string
	loggedBefore []int
	inFlight     []int
}

func (s *recordingSink) trigger(name string) {
	s.triggers = append(s.triggers, name)
	s.loggedBefore = append(s.loggedBefore, len(s.logger.all()))
}

func (s *recordingSink) network(n int) {
	s.inFlight = append(s.inFlight, n)
}
