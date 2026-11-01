// Package rdp wraps the Rust MITM bridge behind the `rdp` build tag.
// Stub builds return ErrRdpUnavailable.
package rdp

import "errors"

var (
	ErrRdpUnavailable = errors.New("rdp bridge: not available in this build")
	ErrInvalidHandle  = errors.New("rdp bridge: invalid handle")
	ErrSessionFailed  = errors.New("rdp bridge: session ended with error")
)


type Bridge struct {
	handle  uint64
	cleanup func()
}

// EventType discriminates the variants in Event.
type EventType uint8

const (
	EventTypeKeyboard    EventType = 1
	EventTypeUnicode     EventType = 2
	EventTypeMouse       EventType = 3
	EventTypeTargetFrame EventType = 4
)

// Action identifies the RDP framing of a TargetFrame event.
type Action uint8

const (
	ActionX224     Action = 0
	ActionFastPath Action = 1
)

// Fields are reused across variants; switch on Type.
type Event struct {
	Type       EventType
	ElapsedNs  uint64
	Scancode   uint8
	CodePoint  uint16
	X          uint16
	Y          uint16
	Flags      uint32
	WheelDelta int32
	Action     Action
	Payload    []byte
}

// PollResult discriminates PollEvent outcomes.
type PollResult uint8

const (
	PollOK      PollResult = 0
	PollTimeout PollResult = 1
	PollEnded   PollResult = 2
)
