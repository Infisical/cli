package webapp

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	Control  byte = 1
	Frame    byte = 2
	Input    byte = 3
	MaxFrame      = (1 << 20) + 64
)

type Direction int

const (
	FromPlatform Direction = iota
	FromViewer
	FromGateway
)

type Attach struct {
	T             string `json:"t"`
	V             uint32 `json:"v"`
	SessionID     string `json:"sessionId"`
	AllocationGen uint32 `json:"allocationGen"`
	ControllerGen uint32 `json:"controllerGen"`
	TakeControl   bool   `json:"takeControl"`
	Actor         struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"actor"`
	IssuedAt string `json:"issuedAt"`
}

type Binding struct {
	AllocationGen uint32 `json:"allocationGen"`
	ControllerGen uint32 `json:"controllerGen"`
	ActorID       string `json:"actorId"`
}

func (a Attach) Validate(sessionID string, binding Binding) error {
	if a.T != "attach" || a.V != 1 || a.SessionID != sessionID || a.Actor.ID == "" || a.Actor.ID != binding.ActorID || a.AllocationGen != binding.AllocationGen || a.ControllerGen != binding.ControllerGen || a.ControllerGen == 0 || a.AllocationGen == 0 {
		return errors.New("attach does not match certificate authority")
	}
	return nil
}

func ValidateFrame(b []byte, direction Direction, attached bool) error {
	if len(b) < 2 || len(b) > MaxFrame {
		return errors.New("invalid frame size")
	}
	switch b[0] {
	case Control, Input:
		limit := 64 << 10
		if b[0] == Input {
			limit = 4 << 10
			if direction == FromGateway {
				return errors.New("wrong INPUT direction")
			}
		}
		if len(b)-1 > limit || !utf8.Valid(b[1:]) || !json.Valid(b[1:]) {
			return errors.New("invalid JSON frame")
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(b[1:], &obj) != nil || obj == nil {
			return errors.New("JSON object required")
		}
		if b[0] == Control {
			var t string
			if json.Unmarshal(obj["t"], &t) != nil || t == "" {
				return errors.New("control type required")
			}
			if t == "attach" && (direction != FromPlatform || attached) {
				return errors.New("unexpected attach")
			}
			if direction == FromViewer || (direction == FromPlatform && attached) {
				switch t {
				case "navigate", "surface", "viewport", "dialog", "end", "ping":
				default:
					return errors.New("forbidden control")
				}
			}
		}
	case Frame:
		if direction != FromGateway || len(b) < 29 || len(b)-29 > 1<<20 {
			return errors.New("invalid display frame")
		}
	default:
		return errors.New("unknown frame type")
	}
	return nil
}

func ReadFrame(r io.Reader, direction Direction, attached bool) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n < 2 || n > MaxFrame {
		return nil, errors.New("invalid frame length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, ValidateFrame(b, direction, attached)
}

func WriteFrame(w io.Writer, b []byte) error {
	if len(b) < 2 || len(b) > MaxFrame {
		return errors.New("invalid frame length")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if err := writeFull(w, h[:]); err != nil {
		return err
	}
	return writeFull(w, b)
}

func ControlFrame(v any) []byte {
	b, _ := json.Marshal(v)
	return append([]byte{Control}, b...)
}
