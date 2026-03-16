package webapp

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Message type bytes shared between the Go handler and the Node.js agent
// (stdin/stdout) and also between the backend and the gateway (relay tunnel).
// Every message is framed: [4-byte big-endian total payload length][1-byte type][payload bytes]
const (
	// Gateway → backend
	MsgTypeFrame    byte = 0x01 // payload: raw JPEG bytes (screencast frame)
	MsgTypePageInfo byte = 0x02 // payload: JSON {"url":"...","title":"..."}

	// Backend → gateway
	MsgTypeMouseMove byte = 0x03 // payload: JSON {"x":f,"y":f}
	MsgTypeMouseDown byte = 0x04 // payload: JSON {"x":f,"y":f,"button":n}
	MsgTypeMouseUp   byte = 0x05 // payload: JSON {"x":f,"y":f,"button":n}
	MsgTypeKeyDown   byte = 0x06 // payload: JSON {"key":"...","code":"...","modifiers":n}
	MsgTypeKeyUp     byte = 0x07 // payload: JSON {"key":"...","code":"...","modifiers":n}
	MsgTypeKeyChar   byte = 0x08 // payload: JSON {"text":"..."}
	MsgTypeScroll    byte = 0x09 // payload: JSON {"x":f,"y":f,"deltaX":f,"deltaY":f}
	MsgTypeResize    byte = 0x0A // payload: JSON {"width":n,"height":n}
	MsgTypeNavigate  byte = 0x0B // payload: JSON {"url":"..."}

	// Agent → Go handler only
	MsgTypeHttpEvent byte = 0x0C // payload: JSON session.HttpEvent

	// Either direction
	MsgTypeClose byte = 0xFF // payload: empty
)

// WriteMessage writes a framed message: [4-byte length][1-byte type][payload].
func WriteMessage(w io.Writer, msgType byte, payload []byte) error {
	totalLen := uint32(1 + len(payload))
	buf := make([]byte, 4+1+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], totalLen)
	buf[4] = msgType
	if len(payload) > 0 {
		copy(buf[5:], payload)
	}
	_, err := w.Write(buf)
	return err
}

// ReadMessage reads a single framed message, returning its type byte and payload.
func ReadMessage(r io.Reader) (byte, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, fmt.Errorf("reading message length: %w", err)
	}
	totalLen := binary.BigEndian.Uint32(lenBuf[:])
	if totalLen == 0 {
		return 0, nil, fmt.Errorf("invalid message: zero length")
	}
	data := make([]byte, totalLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, fmt.Errorf("reading message body: %w", err)
	}
	return data[0], data[1:], nil
}
