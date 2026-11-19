package webapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
)

const linkStyle = `style="display:block;position:absolute;left:0;width:400px;height:100px"`

func testSite() *httptest.Server {
	page := func(title, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!doctype html><html><head><title>%s</title></head><body style="margin:0">%s</body></html>`, title, body)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/{$}", page("Home",
		`<a href="/redirect" `+linkStyle+` id="next">next</a>`+
			`<a href="/popup" target="_blank" `+linkStyle[:len(linkStyle)-1]+`;top:300px">popup</a>`))
	mux.Handle("/second", page("Second", `<a href="http://blocked.invalid/x?token=abc" `+linkStyle+`>out</a>`))
	mux.Handle("/popup", page("Popup", `popup`))
	mux.Handle("/redirect", http.RedirectHandler("/second", http.StatusFound))
	mux.Handle("/long", page("Long",
		`<button onclick="this.textContent='saved';document.body.style.background='#cde'" `+linkStyle+`>save</button>`+
			`<div style="height:6000px;background:linear-gradient(#fff,#333)"></div>`))
	mux.Handle("/form", page("Form",
		`<input autofocus oninput="document.title='v:'+this.value" `+linkStyle+`>`+
			`<button onclick="alert('saved')" `+linkStyle[:len(linkStyle)-1]+`;top:150px">alert</button>`+
			`<input type="file" `+linkStyle[:len(linkStyle)-1]+`;top:300px">`+
			`<a href="/download" `+linkStyle[:len(linkStyle)-1]+`;top:450px">download</a>`))
	mux.HandleFunc("/download", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="report.bin"`)
		w.Write([]byte("data"))
	})
	return httptest.NewServer(mux)
}

type viewer struct {
	t      *testing.T
	done   chan error
	site   string
	logger *session.EncryptedSessionLogger
	key    string
	conn   net.Conn
	json   chan map[string]any
	frames chan []byte
}

func newViewer(t *testing.T, conn net.Conn) *viewer {
	v := &viewer{t: t, conn: conn, json: make(chan map[string]any, 256), frames: make(chan []byte, 1)}
	go func() {
		defer close(v.json)
		for {
			header := make([]byte, frameHeaderBytes)
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}
			payload := make([]byte, binary.BigEndian.Uint32(header[:4])-1)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
			switch header[4] {
			case frameTypeJPEG:
				select {
				case v.frames <- payload:
				default:
					select {
					case <-v.frames:
					default:
					}
					v.frames <- payload
				}
			case frameTypeJSON:
				var msg map[string]any
				if err := json.Unmarshal(payload, &msg); err != nil {
					t.Errorf("server sent invalid JSON: %s", payload)
					return
				}
				v.json <- msg
			default:
				t.Errorf("server sent frame type %d", header[4])
				return
			}
		}
	}()
	return v
}

func (v *viewer) send(msg string) {
	v.t.Helper()
	if _, err := v.conn.Write(clientFrame(frameTypeJSON, msg)); err != nil {
		v.t.Fatalf("send %s: %v", msg, err)
	}
}

// click holds the button for a moment, as a person does. The gateway describes the target from
// the press, and a release that navigates at once would leave it no page to describe.
func (v *viewer) click(x, y int) {
	v.send(fmt.Sprintf(`{"type":"mouse","action":"move","x":%d,"y":%d,"button":"none","buttons":0,"clickCount":0,"deltaX":0,"deltaY":0,"modifiers":0}`, x, y))
	v.send(fmt.Sprintf(`{"type":"mouse","action":"down","x":%d,"y":%d,"button":"left","buttons":1,"clickCount":1,"deltaX":0,"deltaY":0,"modifiers":0}`, x, y))
	time.Sleep(80 * time.Millisecond)
	v.send(fmt.Sprintf(`{"type":"mouse","action":"up","x":%d,"y":%d,"button":"left","buttons":0,"clickCount":1,"deltaX":0,"deltaY":0,"modifiers":0}`, x, y))
}

func (v *viewer) waitFor(what string, match func(map[string]any) bool) map[string]any {
	v.t.Helper()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case msg, ok := <-v.json:
			if !ok {
				v.t.Fatalf("connection closed while waiting for %s", what)
			}
			if msg["type"] == "error" {
				var err error
				select {
				case err = <-v.done:
				case <-time.After(5 * time.Second):
				}
				v.t.Fatalf("server error while waiting for %s: %v (%v)", what, msg, err)
			}
			if match(msg) {
				return msg
			}
			v.t.Logf("while waiting for %s, skipped %v", what, msg)
		case <-timeout:
			v.t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func (v *viewer) waitFrame(what string, match func(width, height int) bool) {
	v.t.Helper()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case frame := <-v.frames:
			cfg, err := jpeg.DecodeConfig(bytes.NewReader(frame))
			if err != nil {
				v.t.Fatalf("frame is not a JPEG: %v", err)
			}
			if match(cfg.Width, cfg.Height) {
				return
			}
		case <-timeout:
			v.t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func isState(url, title string) func(map[string]any) bool {
	return func(m map[string]any) bool {
		return m["type"] == "state" && m["url"] == url && m["title"] == title
	}
}

// processesUsing lists the processes whose command line mentions dir.
func processesUsing(t *testing.T, dir string) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err == nil && bytes.Contains(cmdline, []byte(dir)) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// startBrowserSession runs a session against startPath on the test site. It returns the viewer and
// the directory that holds the browser profiles.
func startBrowserSession(t *testing.T, startPath string) (*viewer, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("checks browser processes through /proc")
	}
	if FindBrowserPath() == "" {
		t.Skip("no browser: set INFISICAL_PAM_BROWSER_PATH or put chromium on PATH")
	}
	profiles := filepath.Join(t.TempDir(), "profiles")
	if err := os.Mkdir(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	// chromedp creates each profile directory under the system temporary directory.
	t.Setenv("TMPDIR", profiles)
	t.Setenv("INFISICAL_PAM_BROWSER_ALLOW_LOOPBACK", "true")
	if os.Geteuid() == 0 {
		t.Setenv(browserNoSandboxEnv, "true")
	}

	site := testSite()
	t.Cleanup(site.Close)

	session.SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { session.SetSessionRecordingPath("") })
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(rawKey)
	expiresAt := time.Now().Add(time.Hour)
	logger, err := session.NewSessionLogger("test-session", key, expiresAt, session.ResourceTypeWebApp, masking.Nop())
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	proxy := NewWebAppProxy(WebAppProxyConfig{
		SessionID:     "test-session",
		StartURL:      site.URL + startPath,
		ExpiresAt:     expiresAt,
		SessionLogger: logger,
	})
	done := make(chan error, 1)
	go func() { done <- proxy.HandleConnection(context.Background(), server) }()
	v := newViewer(t, client)
	v.done = done
	v.site = site.URL
	v.logger = logger
	v.key = key
	return v, profiles
}

// recorded reads back the activity log, which is complete once close has returned.
func (v *viewer) recorded() []session.WebEvent {
	v.t.Helper()
	if err := v.logger.Close(); err != nil {
		v.t.Fatal(err)
	}
	info, err := session.FindSessionFileBySessionID("test-session")
	if err != nil {
		v.t.Fatal(err)
	}
	events, err := session.ReadEncryptedWebEventsFromFile(info.Filename, v.key)
	if err != nil {
		v.t.Fatal(err)
	}
	return events
}

// recordedSoFar reads the activity log while the session still runs. The last record can be half
// written, so a failed read is retried.
func (v *viewer) recordedSoFar() []session.WebEvent {
	v.t.Helper()
	info, err := session.FindSessionFileBySessionID("test-session")
	if err != nil {
		v.t.Fatal(err)
	}
	events, err := session.ReadEncryptedWebEventsFromFile(info.Filename, v.key)
	if err != nil {
		return nil
	}
	return events
}

func (v *viewer) waitRecorded(what string, match func(session.WebEvent) bool) {
	v.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range v.recordedSoFar() {
			if match(ev) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, ev := range v.recordedSoFar() {
		if ev.WebScreenshot != nil {
			ev.JPEG = nil
		}
		raw, _ := json.Marshal(ev)
		v.t.Logf("recorded %s", raw)
	}
	v.t.Fatalf("timed out waiting for a recorded %s", what)
}

func isScreenshot(trigger string) func(session.WebEvent) bool {
	return func(ev session.WebEvent) bool {
		return ev.EventType == session.WebEventScreenshot && ev.Trigger == trigger
	}
}

func checkScreenshot(t *testing.T, ev session.WebEvent) {
	t.Helper()
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(ev.JPEG))
	if err != nil {
		t.Fatalf("%s screenshot is not a JPEG: %v", ev.Trigger, err)
	}
	if cfg.Width != ev.Width || cfg.Height != ev.Height || ev.Bytes != len(ev.JPEG) || ev.Bytes > maxScreenshotBytes {
		t.Errorf("%s screenshot reports %dx%d and %d bytes, image is %dx%d and %d bytes",
			ev.Trigger, ev.Width, ev.Height, ev.Bytes, cfg.Width, cfg.Height, len(ev.JPEG))
	}
}

// indexOf returns the position of the first event that matches, or -1.
func indexOf(events []session.WebEvent, from int, match func(session.WebEvent) bool) int {
	for i := from; i < len(events); i++ {
		if match(events[i]) {
			return i
		}
	}
	return -1
}

func TestBrowserSessionScreenshots(t *testing.T) {
	v, _ := startBrowserSession(t, "/long")
	v.waitFor("state of the long page", isState(v.site+"/long", "Long"))
	v.waitRecorded("navigation screenshot", isScreenshot("navigation"))

	v.click(50, 50)
	v.waitRecorded("click screenshot", isScreenshot("click"))

	v.send(`{"type":"mouse","action":"wheel","x":400,"y":400,"button":"none","buttons":0,"clickCount":0,"deltaX":0,"deltaY":800,"modifiers":0}`)
	v.waitRecorded("scroll screenshot", isScreenshot("scroll"))
	v.close()

	events := v.recorded()
	click := indexOf(events, 0, isAction(session.WebEventInput, "click"))
	clickShot := indexOf(events, max(click, 0), isScreenshot("click"))
	if click < 0 || clickShot < 0 {
		t.Fatalf("click at %d, its screenshot at %d", click, clickShot)
	}
	scroll := indexOf(events, 0, isAction(session.WebEventInput, "scroll"))
	scrollShot := indexOf(events, max(scroll, 0), isScreenshot("scroll"))
	if scroll < 0 || scrollShot < 0 {
		t.Fatalf("scroll at %d, its screenshot at %d", scroll, scrollShot)
	}
	if events[scroll].WebScroll == nil || events[scroll].ScrollY == 0 {
		t.Errorf("scroll = %+v", events[scroll].WebScroll)
	}
	navShot := indexOf(events, 0, isScreenshot("navigation"))
	if nav := indexOf(events, 0, func(ev session.WebEvent) bool { return ev.EventType == session.WebEventNavigation }); nav < 0 || nav > navShot {
		t.Errorf("navigation at %d, its screenshot at %d", nav, navShot)
	}
	for _, i := range []int{navShot, clickShot, scrollShot} {
		checkScreenshot(t, events[i])
	}

	largest := 0
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		largest = max(largest, len(raw))
	}
	if largest > 512<<10 {
		t.Errorf("largest event is %d bytes, over the 512 KiB chunk cap", largest)
	}
	shot := events[clickShot]
	shot.JPEG = shot.JPEG[:12]
	raw, _ := json.Marshal(shot)
	t.Logf("click screenshot (jpeg cut to 12 bytes): %s", raw)
	raw, _ = json.Marshal(events[scroll])
	t.Logf("scroll input: %s", raw)
	t.Logf("largest recorded event: %d bytes; screenshots: %d, %d, %d bytes", largest,
		events[navShot].Bytes, events[clickShot].Bytes, events[scrollShot].Bytes)
}

func findEvent(t *testing.T, events []session.WebEvent, what string, match func(session.WebEvent) bool) session.WebEvent {
	t.Helper()
	for _, ev := range events {
		if match(ev) {
			return ev
		}
	}
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		t.Logf("recorded %s", raw)
	}
	t.Fatalf("no recorded event for %s", what)
	return session.WebEvent{}
}

func isHTTP(url string) func(session.WebEvent) bool {
	return func(ev session.WebEvent) bool { return ev.EventType == session.WebEventHTTP && ev.URL == url }
}

func isAction(eventType session.WebEventType, action string) func(session.WebEvent) bool {
	return func(ev session.WebEvent) bool { return ev.EventType == eventType && ev.Action == action }
}

func (v *viewer) close() {
	v.t.Helper()
	v.conn.Close()
	select {
	case err := <-v.done:
		if err != nil {
			v.t.Errorf("HandleConnection = %v", err)
		}
	case <-time.After(30 * time.Second):
		v.t.Fatal("HandleConnection did not return after the viewer closed")
	}
}

func isNotice(substr string) func(map[string]any) bool {
	return func(m map[string]any) bool {
		msg, _ := m["message"].(string)
		return m["type"] == "notice" && strings.Contains(msg, substr)
	}
}

func TestBrowserSessionInputAndNotices(t *testing.T) {
	v, _ := startBrowserSession(t, "/form")
	v.waitFor("state of the form page", isState(v.site+"/form", "Form"))

	v.click(50, 50)
	for _, key := range []string{`"key":"a","code":"KeyA","keyCode":65`, `"key":"B","code":"KeyB","keyCode":66,"modifiers":8`} {
		v.send(`{"type":"key","action":"down",` + key + `}`)
		v.send(`{"type":"key","action":"up",` + key + `}`)
	}
	v.send(`{"type":"key","action":"down","key":"c","code":"KeyC","keyCode":67,"modifiers":2}`)
	v.send(`{"type":"key","action":"up","key":"c","code":"KeyC","keyCode":67,"modifiers":2}`)
	v.waitFor("typed text in the title", isState(v.site+"/form", "v:aB"))
	v.send(`{"type":"text","text":"pasted"}`)
	v.waitFor("pasted text in the title", isState(v.site+"/form", "v:aBpasted"))

	v.click(50, 200)
	v.waitFor("dialog notice", isNotice("saved"))
	v.click(50, 350)
	v.waitFor("upload notice", isNotice("uploads are blocked"))
	v.click(50, 500)
	v.waitFor("download notice", isNotice("Downloads are blocked"))

	v.click(50, 50)
	v.send(`{"type":"key","action":"down","key":"Enter","code":"Enter","keyCode":13}`)
	v.send(`{"type":"key","action":"up","key":"Enter","code":"Enter","keyCode":13}`)
	v.click(50, 200)
	v.waitFor("dialog notice after Enter", isNotice("saved"))
	v.close()

	events := v.recorded()
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "aBpasted") || strings.Contains(string(raw), `"text":"aB`) {
			t.Errorf("typed or pasted text reached the log: %s", raw)
		}
	}
	paste := findEvent(t, events, "paste", isAction(session.WebEventInput, "paste"))
	if paste.Length != len("pasted") || paste.Target != nil {
		t.Errorf("paste = %+v", paste)
	}
	submit := findEvent(t, events, "submit", isAction(session.WebEventInput, "submit"))
	if submit.Target == nil || submit.Target.Tag != "input" || submit.Target.Role != "textbox" || submit.Target.Text != "" {
		t.Errorf("submit target = %+v", submit.Target)
	}
	inputClick := findEvent(t, events, "click on the input", func(ev session.WebEvent) bool {
		return ev.Action == "click" && ev.Target != nil && ev.Target.Tag == "input"
	})
	if inputClick.Target.Text != "" {
		t.Errorf("click on an input recorded text %q", inputClick.Target.Text)
	}
	dialog := findEvent(t, events, "dialog", isAction(session.WebEventSession, "dialog"))
	if dialog.Detail != "alert" {
		t.Errorf("dialog detail = %q", dialog.Detail)
	}
	findEvent(t, events, "upload.blocked", isAction(session.WebEventSession, "upload.blocked"))
	download := findEvent(t, events, "download.blocked", isAction(session.WebEventSession, "download.blocked"))
	if download.Detail != v.site+"/download" {
		t.Errorf("download detail = %q", download.Detail)
	}
}

func TestBrowserSessionEndToEnd(t *testing.T) {
	v, profiles := startBrowserSession(t, "/")
	site := struct{ URL string }{v.site}

	ready := v.waitFor("ready", func(m map[string]any) bool { return m["type"] == "ready" })
	if ready["width"] != float64(defaultViewportWidth) || ready["height"] != float64(defaultViewportHeight) {
		t.Errorf("ready = %v", ready)
	}
	v.waitFrame("a screencast frame", func(w, h int) bool { return w == defaultViewportWidth && h == defaultViewportHeight })
	start := v.waitFor("state of the start page", isState(site.URL+"/", "Home"))
	if start["canGoBack"] != false || start["canGoForward"] != false {
		t.Errorf("history flags on the start page = %v", start)
	}

	v.click(50, 50)
	second := v.waitFor("state after clicking a link", isState(site.URL+"/second", "Second"))
	if second["canGoBack"] != true || second["canGoForward"] != false {
		t.Errorf("history flags after navigation = %v", second)
	}

	v.click(50, 50)
	blocked := v.waitFor("blocked", func(m map[string]any) bool { return m["type"] == "blocked" })
	if blocked["url"] != "http://blocked.invalid/x?token=***" {
		t.Errorf("blocked url = %v", blocked["url"])
	}

	v.send(`{"type":"text","text":"héllo wörld"}`)

	v.send(`{"type":"navigate","url":"http://blocked.invalid/typed"}`)
	v.waitFor("blocked for a typed URL", func(m map[string]any) bool {
		return m["type"] == "blocked" && m["url"] == "http://blocked.invalid/typed"
	})

	v.send(`{"type":"back"}`)
	home := v.waitFor("state after back", isState(site.URL+"/", "Home"))
	if home["canGoForward"] != true {
		t.Errorf("canGoForward after back = %v", home["canGoForward"])
	}

	v.click(50, 350)
	v.waitFor("pop-up opened in the same tab", isState(site.URL+"/popup", "Popup"))

	v.send(`{"type":"resize","width":800,"height":600}`)
	v.waitFrame("a frame at the new size", func(w, h int) bool { return w == 800 && h == 600 })

	if pids := processesUsing(t, profiles); len(pids) == 0 {
		t.Fatal("found no browser process using the profile directory")
	}

	v.close()
	checkRecording(t, v.recorded(), site.URL)

	if pids := processesUsing(t, profiles); len(pids) > 0 {
		t.Errorf("browser processes left running: %v", pids)
	}
	left, err := os.ReadDir(profiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) > 0 {
		t.Errorf("profile directories left behind: %v", left)
	}
}

func checkRecording(t *testing.T, events []session.WebEvent, site string) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("nothing was recorded")
	}
	first, last := events[0], events[len(events)-1]
	if first.Action != "start" || first.Detail != site+"/" {
		t.Errorf("first event = %+v", first)
	}
	if last.Action != "end" || last.Detail != "viewer disconnected" {
		t.Errorf("last event = %+v", last)
	}
	for i, ev := range events {
		if ev.ChannelType != session.SessionChannelWeb {
			t.Errorf("event %d channel = %q", i, ev.ChannelType)
		}
		if i > 0 && ev.ElapsedTime < events[i-1].ElapsedTime {
			t.Errorf("event %d goes back in time: %v after %v", i, ev.ElapsedTime, events[i-1].ElapsedTime)
		}
	}

	redirect := findEvent(t, events, "redirect hop", isHTTP(site+"/redirect"))
	if redirect.Status != 302 || redirect.Method != "GET" || redirect.ResourceType != "document" {
		t.Errorf("redirect = %+v", *redirect.WebRequest)
	}
	second := findEvent(t, events, "redirect target", isHTTP(site+"/second"))
	if second.Status != 200 || second.MimeType != "text/html" || second.RespBytes == 0 || second.Error != "" {
		t.Errorf("second = %+v", *second.WebRequest)
	}
	blocked := findEvent(t, events, "blocked request", isHTTP("http://blocked.invalid/x?token=***"))
	if !blocked.Blocked || blocked.ResourceType != "document" {
		t.Errorf("blocked = %+v", *blocked.WebRequest)
	}
	findEvent(t, events, "navigation to the start page", func(ev session.WebEvent) bool {
		return ev.EventType == session.WebEventNavigation && ev.URL == site+"/"
	})
	findEvent(t, events, "navigation after the redirect", func(ev session.WebEvent) bool {
		return ev.EventType == session.WebEventNavigation && ev.URL == site+"/second"
	})
	navBlocked := findEvent(t, events, "navigation.blocked", isAction(session.WebEventSession, "navigation.blocked"))
	if navBlocked.Detail != "http://blocked.invalid/x?token=***" {
		t.Errorf("navigation.blocked detail = %q", navBlocked.Detail)
	}
	findEvent(t, events, "typed navigation blocked", func(ev session.WebEvent) bool {
		return ev.Action == "navigation.blocked" && ev.Detail == "http://blocked.invalid/typed"
	})
	click := findEvent(t, events, "click", isAction(session.WebEventInput, "click"))
	if click.X != 50 || click.Y != 50 || click.Target == nil ||
		click.Target.Tag != "a" || click.Target.Role != "link" || click.Target.Name != "next" || click.Target.Text != "next" {
		t.Errorf("click = %+v target %+v", click, click.Target)
	}
	paste := findEvent(t, events, "paste", isAction(session.WebEventInput, "paste"))
	if paste.Length != 11 {
		t.Errorf("paste length = %d, want 11 characters", paste.Length)
	}
	for _, action := range []string{"navigate", "back"} {
		ev := findEvent(t, events, action, isAction(session.WebEventInput, action))
		if ev.X != 0 || ev.Target != nil {
			t.Errorf("%s = %+v", action, ev)
		}
	}
	findEvent(t, events, "popup", isAction(session.WebEventSession, "popup"))

	seen := map[session.WebEventType]bool{}
	for _, ev := range events {
		if !seen[ev.EventType] {
			seen[ev.EventType] = true
			raw, _ := json.Marshal(ev)
			t.Logf("first %s event: %s", ev.EventType, raw)
		}
	}
	for _, ev := range []session.WebEvent{redirect, blocked, click, paste, navBlocked} {
		raw, _ := json.Marshal(ev)
		t.Logf("example: %s", raw)
	}
}
