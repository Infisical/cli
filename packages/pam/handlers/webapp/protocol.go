package webapp

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/chromedp/cdproto/input"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

const (
	frameTypeJPEG byte = 1
	frameTypeJSON byte = 2

	frameHeaderBytes    = 5
	maxClientFrameBytes = 1 << 20

	maxKeyChars     = 64
	maxPasteBytes   = 64 << 10
	maxNavigateURL  = 8 << 10
	minViewportSide = 200
	maxViewportSide = 3840
	maxWheelDelta   = 10000

	modifierMask = 1 | 2 | 4 | 8
	buttonsMask  = 1 | 2 | 4 | 8 | 16
	modifierCtrl = 2
	modifierMeta = 4
)

var errInvalidFrame = errors.New("invalid frame")

// readClientFrame reads one viewer frame and returns its JSON payload. The viewer may only send
// JSON frames, and any other frame is a protocol error that ends the session.
func readClientFrame(r io.Reader) ([]byte, error) {
	var header [frameHeaderBytes]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:4])
	if length < 1 || length > maxClientFrameBytes {
		return nil, fmt.Errorf("%w: length %d", errInvalidFrame, length)
	}
	if header[4] != frameTypeJSON {
		return nil, fmt.Errorf("%w: type %d", errInvalidFrame, header[4])
	}
	payload := make([]byte, length-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return payload, nil
}

type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newFrameWriter(w io.Writer) *frameWriter {
	return &frameWriter{w: w}
}

func (fw *frameWriter) writeFrame(frameType byte, payload []byte) error {
	header := make([]byte, frameHeaderBytes)
	binary.BigEndian.PutUint32(header[:4], uint32(len(payload)+1))
	header[4] = frameType
	buffers := net.Buffers{header, payload}

	fw.mu.Lock()
	defer fw.mu.Unlock()
	_, err := buffers.WriteTo(fw.w)
	return err
}

func (fw *frameWriter) writeJPEG(data []byte) error {
	return fw.writeFrame(frameTypeJPEG, data)
}

func (fw *frameWriter) writeJSON(msg any) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return fw.writeFrame(frameTypeJSON, payload)
}

type readyMessage struct {
	Type   string `json:"type"`
	Width  int64  `json:"width"`
	Height int64  `json:"height"`
}

type stateMessage struct {
	Type         string `json:"type"`
	URL          string `json:"url"`
	Title        string `json:"title"`
	CanGoBack    bool   `json:"canGoBack"`
	CanGoForward bool   `json:"canGoForward"`
}

type noticeMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type blockedMessage struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Message string `json:"message"`
}

type errorMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func newReady(width, height int64) readyMessage {
	return readyMessage{Type: "ready", Width: width, Height: height}
}

func newNotice(message string) noticeMessage {
	return noticeMessage{Type: "notice", Message: message}
}

func newBlocked(rawURL, message string) blockedMessage {
	return blockedMessage{Type: "blocked", URL: session.MaskURL(rawURL), Message: message}
}

func newError(message string) errorMessage {
	return errorMessage{Type: "error", Message: message}
}

type clientMessage struct {
	Type       string  `json:"type"`
	Action     string  `json:"action"`
	X          float64 `json:"x"`
	Y          float64 `json:"y"`
	Button     string  `json:"button"`
	Buttons    int64   `json:"buttons"`
	ClickCount int64   `json:"clickCount"`
	DeltaX     float64 `json:"deltaX"`
	DeltaY     float64 `json:"deltaY"`
	Modifiers  int64   `json:"modifiers"`
	Key        string  `json:"key"`
	Code       string  `json:"code"`
	KeyCode    int64   `json:"keyCode"`
	Text       string  `json:"text"`
	Width      int64   `json:"width"`
	Height     int64   `json:"height"`
	URL        string  `json:"url"`
}

func parseClientMessage(payload []byte) (clientMessage, error) {
	var msg clientMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return clientMessage{}, err
	}
	return msg, nil
}

var mouseActions = map[string]input.DispatchMouseEventType{
	"down":  input.DispatchMouseEventTypeMousePressed,
	"up":    input.DispatchMouseEventTypeMouseReleased,
	"move":  input.DispatchMouseEventTypeMouseMoved,
	"wheel": input.DispatchMouseEventTypeMouseWheel,
}

var mouseButtons = map[string]input.MouseButton{
	"none":    input.MouseButtonNone,
	"left":    input.MouseButtonLeft,
	"middle":  input.MouseButtonMiddle,
	"right":   input.MouseButtonRight,
	"back":    input.MouseButtonBack,
	"forward": input.MouseButtonForward,
}

func clamp[T int64 | float64](v, lo, hi T) T {
	return max(lo, min(v, hi))
}

func (m clientMessage) mouseParams(width, height int64) (input.DispatchMouseEventParams, error) {
	eventType, ok := mouseActions[m.Action]
	if !ok {
		return input.DispatchMouseEventParams{}, fmt.Errorf("unknown mouse action %q", m.Action)
	}
	button := input.MouseButtonNone
	if m.Button != "" {
		if button, ok = mouseButtons[m.Button]; !ok {
			return input.DispatchMouseEventParams{}, fmt.Errorf("unknown mouse button %q", m.Button)
		}
	}
	params := input.DispatchMouseEventParams{
		Type:       eventType,
		X:          clamp(m.X, 0, float64(width-1)),
		Y:          clamp(m.Y, 0, float64(height-1)),
		Modifiers:  m.Modifiers & modifierMask,
		Button:     button,
		Buttons:    m.Buttons & buttonsMask,
		ClickCount: clamp(m.ClickCount, 0, 3),
	}
	if eventType == input.DispatchMouseEventTypeMouseWheel {
		params.DeltaX = clamp(m.DeltaX, -maxWheelDelta, maxWheelDelta)
		params.DeltaY = clamp(m.DeltaY, -maxWheelDelta, maxWheelDelta)
	}
	return params, nil
}

func (m clientMessage) keyParams() (input.DispatchKeyEventParams, error) {
	if utf8.RuneCountInString(m.Key) > maxKeyChars || utf8.RuneCountInString(m.Code) > maxKeyChars {
		return input.DispatchKeyEventParams{}, errors.New("key or code too long")
	}
	keyCode := m.KeyCode
	if keyCode < 0 || keyCode > 255 {
		keyCode = 0
	}
	params := input.DispatchKeyEventParams{
		Modifiers:             m.Modifiers & modifierMask,
		Key:                   m.Key,
		Code:                  m.Code,
		WindowsVirtualKeyCode: keyCode,
		NativeVirtualKeyCode:  keyCode,
	}
	switch m.Action {
	case "down":
		params.Text = keyText(m.Key, params.Modifiers)
		if params.Text != "" {
			params.Type = input.DispatchKeyEventTypeKeyDown
		} else {
			params.Type = input.DispatchKeyEventTypeRawKeyDown
		}
	case "up":
		params.Type = input.DispatchKeyEventTypeKeyUp
	default:
		return input.DispatchKeyEventParams{}, fmt.Errorf("unknown key action %q", m.Action)
	}
	return params, nil
}

// keyText is the text a key press types. A shortcut with Ctrl or Meta types nothing, or the
// page would receive the character as input on top of the shortcut.
func keyText(key string, modifiers int64) string {
	if key == "Enter" {
		return "\r"
	}
	if modifiers&(modifierCtrl|modifierMeta) != 0 {
		return ""
	}
	if utf8.RuneCountInString(key) == 1 {
		return key
	}
	return ""
}

func (m clientMessage) pasteText() (string, error) {
	if m.Text == "" {
		return "", errors.New("empty paste")
	}
	if len(m.Text) > maxPasteBytes {
		return "", errors.New("paste too large")
	}
	return m.Text, nil
}

func (m clientMessage) viewport() (int64, int64) {
	return clamp(m.Width, minViewportSide, maxViewportSide), clamp(m.Height, minViewportSide, maxViewportSide)
}

// navigateURL is the URL a navigate message asks for, with https:// added when it has no scheme.
func (m clientMessage) navigateURL() (string, error) {
	raw := strings.TrimSpace(m.URL)
	if raw == "" {
		return "", errors.New("empty URL")
	}
	if len(raw) > maxNavigateURL {
		return "", errors.New("URL too long")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errSchemeNotAllowed
	}
	return raw, nil
}
