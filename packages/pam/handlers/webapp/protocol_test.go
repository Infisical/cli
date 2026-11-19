package webapp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/chromedp/cdproto/input"
)

func clientFrame(frameType byte, payload string) []byte {
	buf := make([]byte, frameHeaderBytes, frameHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)+1))
	buf[4] = frameType
	return append(buf, payload...)
}

func TestReadClientFrameSplitAcrossReads(t *testing.T) {
	stream := clientFrame(frameTypeJSON, `{"type":"reload"}`)
	r := iotest.OneByteReader(bytes.NewReader(stream))
	payload, err := readClientFrame(r)
	if err != nil {
		t.Fatalf("readClientFrame: %v", err)
	}
	if string(payload) != `{"type":"reload"}` {
		t.Fatalf("payload = %q", payload)
	}
	if _, err := readClientFrame(r); !errors.Is(err, io.EOF) {
		t.Fatalf("after last frame err = %v, want EOF", err)
	}
}

func TestReadClientFrameSeveralFramesInOneRead(t *testing.T) {
	var stream []byte
	stream = append(stream, clientFrame(frameTypeJSON, `{"type":"back"}`)...)
	stream = append(stream, clientFrame(frameTypeJSON, `{"type":"forward"}`)...)
	stream = append(stream, clientFrame(frameTypeJSON, `{}`)...)
	r := bytes.NewReader(stream)
	for _, want := range []string{`{"type":"back"}`, `{"type":"forward"}`, `{}`} {
		payload, err := readClientFrame(r)
		if err != nil {
			t.Fatalf("readClientFrame: %v", err)
		}
		if string(payload) != want {
			t.Fatalf("payload = %q, want %q", payload, want)
		}
	}
}

func TestReadClientFrameRejectsBadFrames(t *testing.T) {
	zeroLength := make([]byte, frameHeaderBytes)
	tooLong := make([]byte, frameHeaderBytes)
	binary.BigEndian.PutUint32(tooLong[:4], maxClientFrameBytes+1)
	tooLong[4] = frameTypeJSON

	cases := map[string][]byte{
		"zero length": zeroLength,
		"over 1 MiB":  tooLong,
		"jpeg type":   clientFrame(frameTypeJPEG, "x"),
		"other type":  clientFrame(9, "x"),
	}
	for name, stream := range cases {
		if _, err := readClientFrame(bytes.NewReader(stream)); !errors.Is(err, errInvalidFrame) {
			t.Errorf("%s: err = %v, want invalid frame", name, err)
		}
	}
}

func TestReadClientFrameAcceptsMaximumLength(t *testing.T) {
	payload := strings.Repeat("a", maxClientFrameBytes-1)
	got, err := readClientFrame(bytes.NewReader(clientFrame(frameTypeJSON, payload)))
	if err != nil {
		t.Fatalf("readClientFrame: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("len = %d", len(got))
	}
}

func TestReadClientFrameTruncated(t *testing.T) {
	stream := clientFrame(frameTypeJSON, `{"type":"reload"}`)
	if _, err := readClientFrame(bytes.NewReader(stream[:len(stream)-2])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want unexpected EOF", err)
	}
	if _, err := readClientFrame(bytes.NewReader(stream[:3])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("header err = %v, want unexpected EOF", err)
	}
}

func TestFrameWriter(t *testing.T) {
	var buf bytes.Buffer
	w := newFrameWriter(&buf)
	if err := w.writeJPEG([]byte{0xff, 0xd8, 0xff}); err != nil {
		t.Fatal(err)
	}
	if err := w.writeJSON(newReady(1280, 800)); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 4, frameTypeJPEG, 0xff, 0xd8, 0xff}
	want = append(want, clientFrame(frameTypeJSON, `{"type":"ready","width":1280,"height":800}`)...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("written = %v\nwant      %v", buf.Bytes(), want)
	}
}

func TestServerMessagesJSON(t *testing.T) {
	var buf bytes.Buffer
	w := newFrameWriter(&buf)
	msgs := []any{
		stateMessage{Type: "state", URL: "https://a/", Title: "A"},
		newNotice("n"),
		newBlocked("https://u:p@evil.example/?token=abc", "m"),
		newError("e"),
	}
	for _, m := range msgs {
		if err := w.writeJSON(m); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	r := bytes.NewReader(buf.Bytes())
	for range msgs {
		header := make([]byte, frameHeaderBytes)
		io.ReadFull(r, header)
		payload := make([]byte, binary.BigEndian.Uint32(header[:4])-1)
		io.ReadFull(r, payload)
		got = append(got, string(payload))
	}
	want := []string{
		`{"type":"state","url":"https://a/","title":"A","canGoBack":false,"canGoForward":false}`,
		`{"type":"notice","message":"n"}`,
		`{"type":"blocked","url":"https://evil.example/?token=***","message":"m"}`,
		`{"type":"error","message":"e"}`,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("message %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func parse(t *testing.T, raw string) clientMessage {
	t.Helper()
	msg, err := parseClientMessage([]byte(raw))
	if err != nil {
		t.Fatalf("parseClientMessage(%s): %v", raw, err)
	}
	return msg
}

func TestMouseParams(t *testing.T) {
	msg := parse(t, `{"type":"mouse","action":"down","x":5000,"y":-20,"button":"left","buttons":255,"clickCount":9,"modifiers":255}`)
	p, err := msg.mouseParams(1280, 800)
	if err != nil {
		t.Fatal(err)
	}
	want := input.DispatchMouseEventParams{
		Type: input.DispatchMouseEventTypeMousePressed, X: 1279, Y: 0,
		Button: input.MouseButtonLeft, Buttons: 31, ClickCount: 3, Modifiers: 15,
	}
	if p != want {
		t.Errorf("params = %+v, want %+v", p, want)
	}

	wheel := parse(t, `{"type":"mouse","action":"wheel","x":10,"y":10,"button":"none","deltaX":-99999,"deltaY":120,"clickCount":-1}`)
	p, err = wheel.mouseParams(1280, 800)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != input.DispatchMouseEventTypeMouseWheel || p.DeltaX != -maxWheelDelta || p.DeltaY != 120 || p.ClickCount != 0 {
		t.Errorf("wheel params = %+v", p)
	}

	move := parse(t, `{"type":"mouse","action":"move","x":1,"y":2,"deltaY":50}`)
	p, err = move.mouseParams(1280, 800)
	if err != nil {
		t.Fatal(err)
	}
	if p.DeltaY != 0 || p.Button != input.MouseButtonNone {
		t.Errorf("move params = %+v", p)
	}

	for _, bad := range []string{
		`{"type":"mouse","action":"drag","x":1,"y":1}`,
		`{"type":"mouse","action":"down","button":"1"}`,
		`{"type":"mouse","action":"down","button":"LEFT"}`,
	} {
		if _, err := parse(t, bad).mouseParams(1280, 800); err == nil {
			t.Errorf("mouseParams(%s) succeeded", bad)
		}
	}
}

func TestKeyParams(t *testing.T) {
	cases := []struct {
		raw      string
		wantType input.DispatchKeyEventType
		wantText string
	}{
		{`{"type":"key","action":"down","key":"a","code":"KeyA","keyCode":65}`, input.DispatchKeyEventTypeKeyDown, "a"},
		{`{"type":"key","action":"down","key":"A","code":"KeyA","keyCode":65,"modifiers":8}`, input.DispatchKeyEventTypeKeyDown, "A"},
		{`{"type":"key","action":"down","key":"é","code":"KeyE","keyCode":69}`, input.DispatchKeyEventTypeKeyDown, "é"},
		{`{"type":"key","action":"down","key":"a","code":"KeyA","keyCode":65,"modifiers":2}`, input.DispatchKeyEventTypeRawKeyDown, ""},
		{`{"type":"key","action":"down","key":"a","code":"KeyA","keyCode":65,"modifiers":4}`, input.DispatchKeyEventTypeRawKeyDown, ""},
		{`{"type":"key","action":"down","key":"a","code":"KeyA","keyCode":65,"modifiers":1}`, input.DispatchKeyEventTypeKeyDown, "a"},
		{`{"type":"key","action":"down","key":"Enter","code":"Enter","keyCode":13}`, input.DispatchKeyEventTypeKeyDown, "\r"},
		{`{"type":"key","action":"down","key":"Tab","code":"Tab","keyCode":9}`, input.DispatchKeyEventTypeRawKeyDown, ""},
		{`{"type":"key","action":"down","key":"ArrowLeft","code":"ArrowLeft","keyCode":37}`, input.DispatchKeyEventTypeRawKeyDown, ""},
		{`{"type":"key","action":"up","key":"a","code":"KeyA","keyCode":65}`, input.DispatchKeyEventTypeKeyUp, ""},
	}
	for _, tc := range cases {
		p, err := parse(t, tc.raw).keyParams()
		if err != nil {
			t.Fatalf("keyParams(%s): %v", tc.raw, err)
		}
		if p.Type != tc.wantType || p.Text != tc.wantText {
			t.Errorf("keyParams(%s) = type %s text %q, want %s %q", tc.raw, p.Type, p.Text, tc.wantType, tc.wantText)
		}
	}

	p, err := parse(t, `{"type":"key","action":"down","key":"a","code":"KeyA","keyCode":65,"modifiers":255}`).keyParams()
	if err != nil {
		t.Fatal(err)
	}
	if p.Modifiers != 15 || p.WindowsVirtualKeyCode != 65 || p.NativeVirtualKeyCode != 65 || p.Code != "KeyA" || p.Key != "a" {
		t.Errorf("params = %+v", p)
	}
	p, err = parse(t, `{"type":"key","action":"down","key":"a","keyCode":99999}`).keyParams()
	if err != nil {
		t.Fatal(err)
	}
	if p.WindowsVirtualKeyCode != 0 {
		t.Errorf("out of range keyCode kept: %d", p.WindowsVirtualKeyCode)
	}

	long := strings.Repeat("k", maxKeyChars+1)
	limit := strings.Repeat("é", maxKeyChars)
	if _, err := parse(t, `{"type":"key","action":"down","key":"`+limit+`","code":"`+limit+`"}`).keyParams(); err != nil {
		t.Errorf("64-character key refused: %v", err)
	}
	for _, bad := range []string{
		`{"type":"key","action":"down","key":"` + long + `"}`,
		`{"type":"key","action":"down","key":"a","code":"` + long + `"}`,
		`{"type":"key","action":"press","key":"a"}`,
	} {
		if _, err := parse(t, bad).keyParams(); err == nil {
			t.Errorf("keyParams accepted %.60s", bad)
		}
	}
}

func TestPasteText(t *testing.T) {
	ok := strings.Repeat("x", maxPasteBytes)
	if text, err := (clientMessage{Type: "text", Text: ok}).pasteText(); err != nil || text != ok {
		t.Errorf("64 KiB paste refused: %v", err)
	}
	if _, err := (clientMessage{Type: "text", Text: ok + "x"}).pasteText(); err == nil {
		t.Error("paste over 64 KiB accepted")
	}
	if _, err := (clientMessage{Type: "text"}).pasteText(); err == nil {
		t.Error("empty paste accepted")
	}
}

func TestViewportClamp(t *testing.T) {
	cases := []struct{ w, h, wantW, wantH int64 }{
		{1024, 768, 1024, 768},
		{10, 100000, 200, 3840},
		{-5, 0, 200, 200},
		{200, 3840, 200, 3840},
	}
	for _, tc := range cases {
		w, h := clientMessage{Width: tc.w, Height: tc.h}.viewport()
		if w != tc.wantW || h != tc.wantH {
			t.Errorf("viewport(%d, %d) = %d, %d", tc.w, tc.h, w, h)
		}
	}
}

func TestNavigateURL(t *testing.T) {
	cases := map[string]string{
		"grafana.internal/d/1":       "https://grafana.internal/d/1",
		"  http://grafana.internal ": "http://grafana.internal",
		"localhost:3000":             "https://localhost:3000",
	}
	for in, want := range cases {
		got, err := clientMessage{URL: in}.navigateURL()
		if err != nil || got != want {
			t.Errorf("navigateURL(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://grafana.internal", "ws://grafana.internal", "https://" + strings.Repeat("a", maxNavigateURL)} {
		if _, err := (clientMessage{URL: bad}).navigateURL(); err == nil {
			t.Errorf("navigateURL(%.40q) succeeded", bad)
		}
	}
	if _, err := (clientMessage{URL: "file:///etc/passwd"}).navigateURL(); err != errSchemeNotAllowed {
		t.Errorf("file URL err = %v, want scheme not allowed", err)
	}
}

func TestParseClientMessageRejectsMalformedJSON(t *testing.T) {
	for _, bad := range []string{`{`, `[]`, `{"type":"resize","width":"wide"}`, `{"type":"resize","width":10.5}`} {
		if _, err := parseClientMessage([]byte(bad)); err == nil {
			t.Errorf("parseClientMessage(%s) succeeded", bad)
		}
	}
}
