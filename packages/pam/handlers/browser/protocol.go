package browser

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Each message is a 4-byte big-endian length covering the type byte and payload, a 1-byte
// type, then the payload. Mirrored by the viewer's browser-protocol.ts.
const (
	// Header: seq uint32, elapsed ms uint32, width uint16, height uint16; then the JPEG.
	MessageFrame byte = 1
	MessageJSON  byte = 2
)

const (
	lengthFieldSize      = 4
	frameHeaderSize      = 12
	MaxClientMessageSize = 64 * 1024
)

// Input coordinates are in the viewport; frames are scaled down to fit MaxFrameWidth by
// MaxFrameHeight.
const (
	DefaultViewportWidth  = 1280
	DefaultViewportHeight = 800
	minViewportWidth      = 320
	minViewportHeight     = 240
	maxViewportWidth      = 3840
	maxViewportHeight     = 2160
	MaxFrameWidth         = 1600
	MaxFrameHeight        = 900
)

// The viewer opens with a resize.
const (
	ClientMouse       = "mouse"
	ClientWheel       = "wheel"
	ClientKey         = "key"
	ClientText        = "text"
	ClientResize      = "resize"
	ClientDialogReply = "dialog_reply"
	ClientEnd         = "end"
)

type ClientMessage struct {
	Type       string  `json:"type"`
	Action     string  `json:"action,omitempty"`
	X          float64 `json:"x,omitempty"`
	Y          float64 `json:"y,omitempty"`
	Button     string  `json:"button,omitempty"`
	Buttons    int     `json:"buttons,omitempty"`
	ClickCount int     `json:"clickCount,omitempty"`
	DeltaX     float64 `json:"deltaX,omitempty"`
	DeltaY     float64 `json:"deltaY,omitempty"`
	Key        string  `json:"key,omitempty"`
	Code       string  `json:"code,omitempty"`
	KeyCode    int     `json:"keyCode,omitempty"`
	Modifiers  int     `json:"modifiers,omitempty"`
	Text       string  `json:"text,omitempty"`
	Width      int     `json:"width,omitempty"`
	Height     int     `json:"height,omitempty"`
	DialogID   int64   `json:"id,omitempty"`
	Accept     bool    `json:"accept,omitempty"`
	PromptText string  `json:"promptText,omitempty"`
}

func (m ClientMessage) input() Input {
	return Input{
		Type:      InputType(m.Type),
		Action:    m.Action,
		X:         m.X,
		Y:         m.Y,
		Button:    m.Button,
		Buttons:   m.Buttons,
		Clicks:    m.ClickCount,
		DeltaX:    m.DeltaX,
		DeltaY:    m.DeltaY,
		Key:       m.Key,
		Code:      m.Code,
		KeyCode:   m.KeyCode,
		Modifiers: m.Modifiers,
		Text:      m.Text,
	}
}

const (
	ServerReady   = "ready"
	ServerURL     = "url"
	ServerCursor  = "cursor"
	ServerDialog  = "dialog"
	ServerBlocked = "blocked"
	ServerEnd     = "end"
)

// The viewer's BrowserEndReason values.
const (
	EndCompleted      = "completed" // maximum session duration reached
	EndExpired        = "expired"
	EndTerminated     = "terminated"
	EndIdle           = "idle"
	EndUserQuit       = "user_quit"
	EndBrowserStopped = "browser_stopped"
	EndCapacity       = "capacity"
	EndError          = "error"

	endViewerDisconnected = "viewer_disconnected"
	endUnknown            = "ended"
)

const blockedHostNotAllowed = "host_not_allowed"

// Exactly the fields the viewer's schema requires; it drops a message missing any of them.
type readyMessage struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

type urlMessage struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Title string `json:"title"`
}

type cursorMessage struct {
	Type   string `json:"type"`
	Cursor string `json:"cursor"`
}

type dialogMessage struct {
	Type          string `json:"type"`
	ID            int64  `json:"id"`
	Kind          string `json:"kind"`
	Message       string `json:"message"`
	DefaultPrompt string `json:"defaultPrompt,omitempty"`
}

type blockedMessage struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Reason string `json:"reason"`
}

type endMessage struct {
	Type    string `json:"type"`
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}

type ServerMessage struct {
	Type          string `json:"type"`
	URL           string `json:"url"`
	Title         string `json:"title"`
	Width         int    `json:"width"`
	Height        int    `json:"height"`
	Cursor        string `json:"cursor"`
	ID            int64  `json:"id"`
	Kind          string `json:"kind"`
	Message       string `json:"message"`
	DefaultPrompt string `json:"defaultPrompt"`
	Reason        string `json:"reason"`
}

type FrameHeader struct {
	Seq       uint32
	ElapsedMs uint32
	Width     uint16
	Height    uint16
}

func WriteMessage(w io.Writer, messageType byte, parts ...[]byte) error {
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	buf := make([]byte, lengthFieldSize+1, lengthFieldSize+1+size)
	binary.BigEndian.PutUint32(buf, uint32(size+1))
	buf[lengthFieldSize] = messageType
	for _, part := range parts {
		buf = append(buf, part...)
	}
	_, err := w.Write(buf)
	return err
}

func ReadMessage(r io.Reader, maxSize int) (byte, []byte, error) {
	var header [lengthFieldSize + 1]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[:lengthFieldSize])
	// It covers the type byte, so zero means the stream is out of step.
	if length == 0 {
		return 0, nil, errors.New("message length of zero")
	}
	if length-1 > uint32(maxSize) {
		return 0, nil, fmt.Errorf("message of %d bytes exceeds the %d byte limit", length-1, maxSize)
	}
	payload := make([]byte, length-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[lengthFieldSize], payload, nil
}

func WriteFrame(w io.Writer, header FrameHeader, jpeg []byte) error {
	var encoded [frameHeaderSize]byte
	binary.BigEndian.PutUint32(encoded[0:4], header.Seq)
	binary.BigEndian.PutUint32(encoded[4:8], header.ElapsedMs)
	binary.BigEndian.PutUint16(encoded[8:10], header.Width)
	binary.BigEndian.PutUint16(encoded[10:12], header.Height)
	return WriteMessage(w, MessageFrame, encoded[:], jpeg)
}

func DecodeFrame(payload []byte) (FrameHeader, []byte, error) {
	if len(payload) < frameHeaderSize {
		return FrameHeader{}, nil, errors.New("frame shorter than its header")
	}
	return FrameHeader{
		Seq:       binary.BigEndian.Uint32(payload[0:4]),
		ElapsedMs: binary.BigEndian.Uint32(payload[4:8]),
		Width:     binary.BigEndian.Uint16(payload[8:10]),
		Height:    binary.BigEndian.Uint16(payload[10:12]),
	}, payload[frameHeaderSize:], nil
}

func writeJSON(w io.Writer, message any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return WriteMessage(w, MessageJSON, data)
}

// Same limits as the viewer's clampViewport.
func clampViewport(width, height int) (int, int) {
	if width <= 0 || height <= 0 {
		return DefaultViewportWidth, DefaultViewportHeight
	}
	return min(max(width, minViewportWidth), maxViewportWidth), min(max(height, minViewportHeight), maxViewportHeight)
}
