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
	"slices"
	"testing"
	"time"
)

const benchPage = `<!doctype html><html><head><title>Bench</title><style>
body{margin:0;height:100vh;background:#00f}
#spin{position:absolute;right:20px;bottom:20px;width:120px;height:120px;background:#0a0;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head><body onmousemove="document.body.style.background = event.clientX < 640 ? '#f00' : '#00f'">
%s</body></html>`

type benchFrame struct {
	at   time.Time
	data []byte
}

// TestViewerLatencyBenchmark measures how long a mouse move takes to show up in a frame, and the
// frame rate while the page animates. It needs a browser and is opt-in, because the numbers
// depend on the machine.
func TestViewerLatencyBenchmark(t *testing.T) {
	if os.Getenv("INFISICAL_PAM_BROWSER_BENCH") != "1" {
		t.Skip("set INFISICAL_PAM_BROWSER_BENCH=1 to run the viewer benchmark")
	}
	if FindBrowserPath() == "" {
		t.Skip("no browser: set INFISICAL_PAM_BROWSER_PATH or put chromium on PATH")
	}
	for _, scale := range []float64{1, 2} {
		t.Run(fmt.Sprintf("deviceScaleFactor=%v", scale), func(t *testing.T) { benchmarkViewer(t, scale) })
	}
}

func benchmarkViewer(t *testing.T, scale float64) {
	profiles := filepath.Join(t.TempDir(), "profiles")
	if err := os.Mkdir(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", profiles)
	t.Setenv("INFISICAL_PAM_BROWSER_ALLOW_LOOPBACK", "true")
	if os.Geteuid() == 0 {
		t.Setenv(browserNoSandboxEnv, "true")
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		spinner := ""
		if r.URL.Path == "/animated" {
			spinner = `<div id="spin"></div>`
		}
		fmt.Fprintf(w, benchPage, spinner)
	}))
	defer site.Close()

	server, client := net.Pipe()
	defer client.Close()
	proxy := NewWebAppProxy(WebAppProxyConfig{SessionID: "bench", StartURL: site.URL + "/", SessionLogger: &memLogger{}})
	done := make(chan error, 1)
	go func() { done <- proxy.HandleConnection(context.Background(), server) }()

	frames := make(chan benchFrame, 4096)
	messages := make(chan map[string]any, 256)
	go func() {
		for {
			header := make([]byte, frameHeaderBytes)
			if _, err := io.ReadFull(client, header); err != nil {
				close(frames)
				return
			}
			payload := make([]byte, binary.BigEndian.Uint32(header[:4])-1)
			if _, err := io.ReadFull(client, payload); err != nil {
				close(frames)
				return
			}
			if header[4] == frameTypeJPEG {
				frames <- benchFrame{at: time.Now(), data: payload}
				continue
			}
			var msg map[string]any
			if json.Unmarshal(payload, &msg) == nil {
				messages <- msg
			}
		}
	}()
	send := func(msg string) {
		if _, err := client.Write(clientFrame(frameTypeJSON, msg)); err != nil {
			t.Fatal(err)
		}
	}
	send(fmt.Sprintf(`{"type":"resize","width":1280,"height":800,"deviceScaleFactor":%v}`, scale))

	deadline := time.After(20 * time.Second)
	for loaded := false; !loaded; {
		select {
		case msg := <-messages:
			loaded = msg["type"] == "state" && msg["title"] == "Bench"
		case <-deadline:
			t.Fatal("the page did not load")
		}
	}
	drain := func() {
		for {
			select {
			case <-frames:
			case <-time.After(300 * time.Millisecond):
				return
			}
		}
	}
	drain()

	const iterations = 50
	var latencies []time.Duration
	for i := range iterations {
		x, wantRed := 1000, false
		if i%2 == 0 {
			x, wantRed = 200, true
		}
		start := time.Now()
		send(fmt.Sprintf(`{"type":"mouse","action":"move","x":%d,"y":400,"button":"none","buttons":0,"clickCount":0,"deltaX":0,"deltaY":0,"modifiers":0}`, x))
		timeout := time.After(5 * time.Second)
		for seen := false; !seen; {
			select {
			case f, ok := <-frames:
				if !ok {
					t.Fatal("connection closed")
				}
				if isRed(t, f.data) == wantRed {
					latencies = append(latencies, f.at.Sub(start))
					seen = true
				}
			case <-timeout:
				t.Fatalf("iteration %d: no frame showed the change", i)
			}
		}
		drain()
	}

	send(`{"type":"navigate","url":"` + site.URL + `/animated"}`)
	time.Sleep(time.Second)
	animated := countFrames(t, frames, 3*time.Second)

	slices.Sort(latencies)
	p50 := latencies[len(latencies)/2]
	p95 := latencies[len(latencies)*95/100]
	t.Logf("mouse move to frame over %d moves: p50 %v, p95 %v, min %v, max %v", len(latencies), p50, p95, latencies[0], latencies[len(latencies)-1])
	t.Logf("frames per second while animating: %.1f", animated)

	client.Close()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("HandleConnection did not return")
	}
}

func countFrames(t *testing.T, frames <-chan benchFrame, window time.Duration) float64 {
	t.Helper()
	end := time.After(window)
	count := 0
	for {
		select {
		case _, ok := <-frames:
			if !ok {
				t.Fatal("connection closed")
			}
			count++
		case <-end:
			return float64(count) / window.Seconds()
		}
	}
}

func isRed(t *testing.T, data []byte) bool {
	t.Helper()
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("frame is not a JPEG: %v", err)
	}
	b := img.Bounds()
	r, g, bl, _ := img.At(b.Min.X+b.Dx()/2, b.Min.Y+b.Dy()/2).RGBA()
	return r>>8 > 200 && g>>8 < 80 && bl>>8 < 80
}
