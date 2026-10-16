package cdp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/browser"
	// Aliased: this package has a session type of its own.
	pamsession "github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/stretchr/testify/require"
)

type viewerFrame struct {
	header browser.FrameHeader
	image  image.Image
}

type recordingLogger struct {
	mu     sync.Mutex
	events []pamsession.SessionEvent
}

func (l *recordingLogger) LogEntry(entry pamsession.SessionLogEntry) error { return nil }

func (l *recordingLogger) LogSessionEvent(event pamsession.SessionEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	return nil
}

func (l *recordingLogger) LogHttpEvent(event pamsession.HttpEvent) error { return nil }

func (l *recordingLogger) Close() error { return nil }

func (l *recordingLogger) ofType(t *testing.T, envelopeType string) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var matching []map[string]any
	for _, event := range l.events {
		var envelope map[string]any
		require.NoError(t, json.Unmarshal(event.Data, &envelope))
		if envelope["type"] == envelopeType {
			matching = append(matching, envelope)
		}
	}
	return matching
}

func TestBrowserProxyStreamsFramesThatFollowInput(t *testing.T) {
	binary := browser.BinaryPath()
	if binary == "" {
		t.Skipf("no browser binary found; set %s to run this test", browser.BinaryEnvName)
	}

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Stream test</title></head>
<body style="margin:0;height:100vh;background:rgb(255,255,255)">
<input type="password" placeholder="Password" style="position:absolute;top:10px;left:10px;width:200px;height:30px">
<script>
document.addEventListener("mousedown", () => { document.body.style.background = "rgb(255,0,0)"; });
document.addEventListener("keydown", (event) => { if (event.key === "b") document.body.style.background = "rgb(0,0,255)"; });
</script></body></html>`)
	}))
	defer app.Close()

	pool := NewPool(NewExecLauncher(ExecLauncherConfig{
		BinaryPath:  binary,
		ProfileRoot: t.TempDir(),
		NoSandbox:   os.Geteuid() == 0,
	}), PoolConfig{})
	defer pool.Close()

	logger := &recordingLogger{}
	proxy := browser.NewBrowserProxy(browser.BrowserProxyConfig{
		SessionID:             "stream-test",
		TargetURL:             app.URL,
		TLSRejectUnauthorized: true,
		Engine:                NewEngine(pool),
		SessionLogger:         logger,
	})
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- proxy.HandleConnection(t.Context(), server) }()

	send := func(message browser.ClientMessage) {
		t.Helper()
		data, err := json.Marshal(message)
		require.NoError(t, err)
		require.NoError(t, browser.WriteMessage(client, browser.MessageJSON, data))
	}

	// Read continuously, like the viewer.
	frames := make(chan viewerFrame, 1)
	messages := make(chan browser.ServerMessage, 64)
	go func() {
		defer close(frames)
		for {
			messageType, payload, err := browser.ReadMessage(client, 16<<20)
			if err != nil {
				return
			}
			if messageType == browser.MessageJSON {
				var message browser.ServerMessage
				if json.Unmarshal(payload, &message) == nil {
					select {
					case messages <- message:
					default:
					}
				}
				continue
			}
			header, data, err := browser.DecodeFrame(payload)
			if err != nil {
				continue
			}
			decoded, err := jpeg.Decode(bytes.NewReader(data))
			if err != nil {
				continue
			}
			select {
			case <-frames:
			default:
			}
			frames <- viewerFrame{header: header, image: decoded}
		}
	}()

	waitForMessage := func(description string, match func(browser.ServerMessage) bool) browser.ServerMessage {
		t.Helper()
		deadline := time.After(15 * time.Second)
		for {
			select {
			case message := <-messages:
				if match(message) {
					return message
				}
			case <-deadline:
				t.Fatalf("no message: %s", description)
			}
		}
	}
	waitForFrame := func(description string, match func(viewerFrame) bool) {
		t.Helper()
		deadline := time.After(15 * time.Second)
		for {
			select {
			case frame, ok := <-frames:
				require.True(t, ok, "connection closed while waiting for %s", description)
				if match(frame) {
					return
				}
			case <-deadline:
				t.Fatalf("no frame showed %s", description)
			}
		}
	}
	centre := func(frame viewerFrame) color.RGBA {
		bounds := frame.image.Bounds()
		return color.RGBAModel.Convert(frame.image.At(bounds.Dx()/2, bounds.Dy()/2)).(color.RGBA)
	}

	send(browser.ClientMessage{Type: browser.ClientResize, Width: 800, Height: 600})
	ready := waitForMessage("ready", func(m browser.ServerMessage) bool { return m.Type == browser.ServerReady })
	require.Equal(t, browser.ServerMessage{Type: browser.ServerReady, URL: app.URL, Width: 800, Height: 600}, ready)
	waitForMessage("the page's title", func(m browser.ServerMessage) bool {
		return m.Type == browser.ServerURL && m.Title == "Stream test"
	})
	waitForFrame("the page at the viewer's size", func(frame viewerFrame) bool {
		c := centre(frame)
		return frame.header.Width == 800 && frame.header.Height == 600 && c.R > 230 && c.G > 230 && c.B > 230
	})

	send(browser.ClientMessage{Type: browser.ClientMouse, Action: "down", X: 400, Y: 300, Button: "left", Buttons: 1, ClickCount: 1})
	send(browser.ClientMessage{Type: browser.ClientMouse, Action: "up", X: 400, Y: 300, Button: "left", ClickCount: 1})
	waitForFrame("the page turned red by the click", func(frame viewerFrame) bool {
		c := centre(frame)
		return c.R > 200 && c.G < 60 && c.B < 60
	})

	// Into the password field.
	send(browser.ClientMessage{Type: browser.ClientMouse, Action: "down", X: 50, Y: 25, Button: "left", Buttons: 1, ClickCount: 1})
	send(browser.ClientMessage{Type: browser.ClientMouse, Action: "up", X: 50, Y: 25, Button: "left", ClickCount: 1})
	send(browser.ClientMessage{Type: browser.ClientKey, Action: "down", Key: "b", Code: "KeyB", KeyCode: 66, Text: "b"})
	send(browser.ClientMessage{Type: browser.ClientKey, Action: "up", Key: "b", Code: "KeyB", KeyCode: 66})
	waitForFrame("the page turned blue by the key press", func(frame viewerFrame) bool {
		c := centre(frame)
		return c.B > 200 && c.R < 60 && c.G < 60
	})

	// Larger than the frame cap, so the frame is scaled down.
	send(browser.ClientMessage{Type: browser.ClientResize, Width: 1920, Height: 1080})
	waitForFrame("the 1920x1080 viewport scaled into a 1600x900 frame", func(frame viewerFrame) bool {
		bounds := frame.image.Bounds()
		return frame.header.Width == 1920 && frame.header.Height == 1080 &&
			bounds.Dx() == browser.MaxFrameWidth && bounds.Dy() == browser.MaxFrameHeight
	})

	send(browser.ClientMessage{Type: browser.ClientEnd})
	end := waitForMessage("the session's end", func(m browser.ServerMessage) bool { return m.Type == browser.ServerEnd })
	require.Equal(t, browser.EndUserQuit, end.Reason)
	require.NoError(t, <-done)

	starts := logger.ofType(t, "session_start")
	require.Len(t, starts, 1)
	require.Equal(t, app.URL, starts[0]["url"])
	require.NotEmpty(t, logger.ofType(t, "frame"))
	var sawTitledNavigation bool
	for _, navigation := range logger.ofType(t, "navigation") {
		sawTitledNavigation = sawTitledNavigation || (navigation["url"] == app.URL+"/" && navigation["title"] == "Stream test")
	}
	require.True(t, sawTitledNavigation, "the page load should be recorded with its title")

	var sawDocument bool
	for _, request := range logger.ofType(t, "http_request") {
		sawDocument = sawDocument || (request["resourceType"] == "Document" && request["method"] == "GET")
	}
	require.True(t, sawDocument, "the page load should be in the request log")

	inputs := logger.ofType(t, "input")
	var clickTargets []any
	var keys []map[string]any
	for _, input := range inputs {
		switch input["kind"] {
		case "click":
			clickTargets = append(clickTargets, input["target"])
		case "key":
			keys = append(keys, input)
		}
	}
	require.Contains(t, clickTargets, `"Password" field`)
	require.Len(t, keys, 1)
	require.Equal(t, `"Password" field`, keys[0]["target"])
	require.Equal(t, "•••", keys[0]["text"], "what's typed into a password field is never recorded")

	ends := logger.ofType(t, "session_end")
	require.Len(t, ends, 1)
	require.Equal(t, browser.EndUserQuit, ends[0]["reason"])
}
