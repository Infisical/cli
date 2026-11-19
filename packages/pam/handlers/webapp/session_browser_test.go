package webapp

import (
	"bytes"
	"context"
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
		`<a href="/second" `+linkStyle+` id="next">next</a>`+
			`<a href="/popup" target="_blank" `+linkStyle[:len(linkStyle)-1]+`;top:300px">popup</a>`))
	mux.Handle("/second", page("Second", `<a href="http://blocked.invalid/x?token=abc" `+linkStyle+`>out</a>`))
	mux.Handle("/popup", page("Popup", `popup`))
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

func (v *viewer) click(x, y int) {
	v.send(fmt.Sprintf(`{"type":"mouse","action":"move","x":%d,"y":%d,"button":"none","buttons":0,"clickCount":0,"deltaX":0,"deltaY":0,"modifiers":0}`, x, y))
	v.send(fmt.Sprintf(`{"type":"mouse","action":"down","x":%d,"y":%d,"button":"left","buttons":1,"clickCount":1,"deltaX":0,"deltaY":0,"modifiers":0}`, x, y))
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

	server, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	proxy := NewWebAppProxy(WebAppProxyConfig{SessionID: "test-session", StartURL: site.URL + startPath})
	done := make(chan error, 1)
	go func() { done <- proxy.HandleConnection(context.Background(), server) }()
	v := newViewer(t, client)
	v.done = done
	v.site = site.URL
	return v, profiles
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
	defer v.close()
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
