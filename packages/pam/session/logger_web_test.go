package session

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
	"github.com/go-resty/resty/v2"
)

func testKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func newWebLogger(t *testing.T, key string, masker masking.Masker) (*EncryptedSessionLogger, *SessionFileInfo) {
	t.Helper()
	setupTestDir(t)
	logger, err := NewSessionLogger("web-sess", key, time.Now().Add(time.Hour), ResourceTypeWebApp, masker)
	if err != nil {
		t.Fatal(err)
	}
	info, err := FindSessionFileBySessionID("web-sess")
	if err != nil {
		t.Fatal(err)
	}
	if info.ResourceType != ResourceTypeWebApp {
		t.Fatalf("resource type parsed from the file name = %q", info.ResourceType)
	}
	return logger, info
}

func TestLogWebEventMasking(t *testing.T) {
	key := testKey(t)
	masker := masking.New([]*regexp.Regexp{regexp.MustCompile(`alice@example\.com`)}, false, nil, "web-sess")
	logger, info := newWebLogger(t, key, masker)

	jpeg := []byte("alice@example.com inside image bytes")
	events := []WebEvent{
		{
			EventType:  WebEventHTTP,
			URL:        "https://bob:pw@grafana.internal/api/search?query=alice@example.com&limit=5#q=1",
			WebRequest: &WebRequest{Method: "GET", Status: 0, Error: "lookup failed for alice@example.com"},
		},
		{EventType: WebEventSession, Action: "navigation.blocked", Detail: "https://evil.example/?u=*** for alice@example.com"},
		{
			EventType: WebEventInput, Action: "click", X: 3, Y: 4,
			Target: &WebTarget{Tag: "a", Role: "link", Name: "Profile of alice@example.com", Text: "alice@example.com"},
		},
		{EventType: WebEventScreenshot, WebScreenshot: &WebScreenshot{Trigger: "click", Width: 1, Height: 1, Bytes: len(jpeg), JPEG: jpeg}},
		{EventType: WebEventNavigation, URL: "https://grafana.internal/" + strings.Repeat("a", 3000)},
	}
	for _, ev := range events {
		if err := logger.LogWebEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	if events[2].Target.Name != "Profile of alice@example.com" {
		t.Error("LogWebEvent changed the caller's target")
	}
	logger.Close()

	got, err := ReadEncryptedWebEventsFromFile(info.Filename, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("read %d events", len(got))
	}
	for _, ev := range got {
		if ev.ChannelType != SessionChannelWeb || ev.Timestamp.IsZero() || ev.ElapsedTime <= 0 {
			t.Errorf("common fields = %+v", ev)
		}
	}
	if got[0].URL != "https://grafana.internal/api/search?query=***&limit=***#q=***" {
		t.Errorf("url = %q", got[0].URL)
	}
	if got[0].Error != "lookup failed for [MASKED]" || got[0].Method != "GET" {
		t.Errorf("request = %+v", got[0].WebRequest)
	}
	if got[1].Detail != "https://evil.example/?u=*** for [MASKED]" {
		t.Errorf("detail = %q", got[1].Detail)
	}
	if got[2].Target.Name != "Profile of [MASKED]" || got[2].Target.Text != "[MASKED]" || got[2].Target.Tag != "a" {
		t.Errorf("target = %+v", got[2].Target)
	}
	if got[3].WebScreenshot == nil || !bytes.Equal(got[3].JPEG, jpeg) || got[3].Trigger != "click" {
		t.Errorf("screenshot was changed: %+v", got[3].WebScreenshot)
	}
	if n := len([]rune(got[4].URL)); n != maxWebEventURLChars {
		t.Errorf("url length = %d", n)
	}
}

func TestWebEventJSONShape(t *testing.T) {
	ts := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	cases := map[string]WebEvent{
		`{"timestamp":"2026-11-19T12:00:00Z","eventType":"http","channelType":"web","elapsedTime":1.5,"url":"https://a/","method":"GET","status":0,"mimeType":"","resourceType":"document","respBytes":0,"durationMs":0,"error":"unfinished"}`: {
			Timestamp: ts, EventType: WebEventHTTP, ChannelType: SessionChannelWeb, ElapsedTime: 1.5, URL: "https://a/",
			WebRequest: &WebRequest{Method: "GET", ResourceType: "document", Error: "unfinished"},
		},
		`{"timestamp":"2026-11-19T12:00:00Z","eventType":"navigation","channelType":"web","elapsedTime":2,"url":"https://a/b"}`: {
			Timestamp: ts, EventType: WebEventNavigation, ChannelType: SessionChannelWeb, ElapsedTime: 2, URL: "https://a/b",
		},
		`{"timestamp":"2026-11-19T12:00:00Z","eventType":"input","channelType":"web","elapsedTime":3,"action":"paste","length":4}`: {
			Timestamp: ts, EventType: WebEventInput, ChannelType: SessionChannelWeb, ElapsedTime: 3, Action: "paste", Length: 4,
		},
	}
	for want, ev := range cases {
		got, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("json = %s\nwant   %s", got, want)
		}
	}
}

func TestUploadSessionFileWebApp(t *testing.T) {
	key := testKey(t)
	logger, info := newWebLogger(t, key, masking.Nop())
	if err := logger.LogWebEvent(WebEvent{EventType: WebEventNavigation, URL: "https://grafana.internal/d/1"}); err != nil {
		t.Fatal(err)
	}
	if err := logger.LogWebEvent(WebEvent{EventType: WebEventHTTP, URL: "https://grafana.internal/api", WebRequest: &WebRequest{Method: "POST", Status: 201}}); err != nil {
		t.Fatal(err)
	}
	logger.Close()

	var body []byte
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	orig := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	defer func() { config.INFISICAL_URL = orig }()

	cm := newTestCredentialsManager(t)
	cm.sessionEncryptionKey = key
	su := NewSessionUploader(resty.New(), cm)
	if err := su.uploadSessionFile(info); err != nil {
		t.Fatal(err)
	}

	if path != "/api/v1/pam/sessions/web-sess/logs" {
		t.Errorf("path = %s", path)
	}
	var req struct {
		Logs []map[string]any `json:"logs"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	if len(req.Logs) != 2 {
		t.Fatalf("logs = %s", body)
	}
	if req.Logs[0]["eventType"] != "navigation" || req.Logs[0]["url"] != "https://grafana.internal/d/1" || req.Logs[0]["channelType"] != "web" {
		t.Errorf("first log = %v", req.Logs[0])
	}
	if req.Logs[1]["method"] != "POST" || req.Logs[1]["status"] != float64(201) {
		t.Errorf("second log = %v", req.Logs[1])
	}
	if _, ok := req.Logs[0]["input"]; ok {
		t.Error("web events were uploaded as database entries")
	}
}

func TestChunkPackingWithLargeWebEvents(t *testing.T) {
	key := testKey(t)
	logger, info := newWebLogger(t, key, masking.Nop())
	// The gateway refuses screenshots over 300 KB, so this is the largest event it writes.
	image := bytes.Repeat([]byte{0xff}, 300<<10)
	for range 3 {
		event := WebEvent{
			EventType:     WebEventScreenshot,
			WebScreenshot: &WebScreenshot{Trigger: "navigation", Width: 1280, Height: 800, Bytes: len(image), JPEG: image},
		}
		if err := logger.LogWebEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	logger.Close()

	offset := int64(0)
	for i := range 3 {
		payload, next, _, _, err := readFromOffset(info.Filename, key, offset, pamPostgresMaxPlaintextBytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) > pamPostgresMaxPlaintextBytes {
			t.Errorf("chunk %d is %d bytes, over the %d cap", i, len(payload), pamPostgresMaxPlaintextBytes)
		}
		t.Logf("chunk %d: %d bytes of %d", i, len(payload), pamPostgresMaxPlaintextBytes)
		var entries []json.RawMessage
		if err := json.Unmarshal(payload, &entries); err != nil || len(entries) != 1 {
			t.Errorf("chunk %d holds %d events, want 1", i, len(entries))
		}
		offset = next
	}
}
