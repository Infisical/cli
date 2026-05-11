package rdp

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type RDPProxyConfig struct {
	TargetHost     string
	TargetPort     uint16
	InjectUsername string
	InjectPassword string
	// Empty for local accounts; AD domain name (e.g. "CORP.EXAMPLE.COM") for
	// domain-joined NTLM CredSSP. Backend session credentials populate this.
	InjectDomain string
	SessionID    string
	SessionLogger session.SessionLogger
	// Added to every event's elapsed_ns so timestamps stay monotonic across
	// RDP reconnects within the same PAM session. Zero for the first connection.
	PriorElapsedNs uint64
}

type RDPProxy struct {
	config RDPProxyConfig
}

func NewRDPProxy(config RDPProxyConfig) *RDPProxy {
	return &RDPProxy{config: config}
}

// Wire envelopes carried inside TerminalEvent.Data for ChannelType=RDP.
type rdpTargetFrameEnvelope struct {
	Type      string `json:"type"`    // "target_frame"
	Action    string `json:"action"`  // "x224" | "fastpath"
	Payload   []byte `json:"payload"` // raw PDU bytes (base64 by Go's json.Marshal)
	ElapsedNs uint64 `json:"elapsedNs"`
}

type rdpKeyboardEnvelope struct {
	Type      string `json:"type"` // "keyboard"
	Scancode  uint8  `json:"scancode"`
	Flags     uint32 `json:"flags"`
	ElapsedNs uint64 `json:"elapsedNs"`
}

type rdpUnicodeEnvelope struct {
	Type      string `json:"type"` // "unicode"
	CodePoint uint16 `json:"codePoint"`
	Flags     uint32 `json:"flags"`
	ElapsedNs uint64 `json:"elapsedNs"`
}

type rdpMouseEnvelope struct {
	Type       string `json:"type"` // "mouse"
	X          uint16 `json:"x"`
	Y          uint16 `json:"y"`
	Flags      uint32 `json:"flags"`
	WheelDelta int32  `json:"wheelDelta"`
	ElapsedNs  uint64 `json:"elapsedNs"`
}

// Bounds bridge poll latency so Cancel ends the drain loop promptly.
const pollTimeout = 250 * time.Millisecond

var errUnknownRdpEventType = errors.New("rdp: unknown event type")

// Logger errors are warned but don't stop the drain; dropping one event is
// better than back-pressuring the bridge byte stream.
func drainBridgeEvents(ctx context.Context, b *Bridge, logger session.SessionLogger, sessionID string, priorElapsedNs uint64) {
	if logger == nil {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		result, ev, err := b.PollEvent(pollTimeout)
		if err != nil {
			log.Debug().Err(err).Str("sessionID", sessionID).Msg("rdp event drain stopped")
			return
		}
		switch result {
		case PollEnded:
			return
		case PollTimeout:
			continue
		case PollOK:
			ev.ElapsedNs += priorElapsedNs
			data, encErr := encodeRdpEvent(ev)
			if encErr != nil {
				log.Warn().Err(encErr).Str("sessionID", sessionID).Uint8("type", uint8(ev.Type)).Msg("encode RDP event")
				continue
			}
			te := session.TerminalEvent{
				Timestamp:   time.Now(),
				EventType:   session.TerminalEventRDP,
				ChannelType: session.TerminalChannelRDP,
				Data:        data,
				ElapsedTime: float64(ev.ElapsedNs) / 1e9,
			}
			if logErr := logger.LogTerminalEvent(te); logErr != nil {
				log.Warn().Err(logErr).Str("sessionID", sessionID).Msg("log RDP event")
			}
		}
	}
}

func encodeRdpEvent(ev Event) ([]byte, error) {
	switch ev.Type {
	case EventTypeTargetFrame:
		action := "x224"
		if ev.Action == ActionFastPath {
			action = "fastpath"
		}
		return json.Marshal(rdpTargetFrameEnvelope{
			Type:      "target_frame",
			Action:    action,
			Payload:   ev.Payload,
			ElapsedNs: ev.ElapsedNs,
		})
	case EventTypeKeyboard:
		return json.Marshal(rdpKeyboardEnvelope{
			Type:      "keyboard",
			Scancode:  ev.Scancode,
			Flags:     ev.Flags,
			ElapsedNs: ev.ElapsedNs,
		})
	case EventTypeUnicode:
		return json.Marshal(rdpUnicodeEnvelope{
			Type:      "unicode",
			CodePoint: ev.CodePoint,
			Flags:     ev.Flags,
			ElapsedNs: ev.ElapsedNs,
		})
	case EventTypeMouse:
		return json.Marshal(rdpMouseEnvelope{
			Type:       "mouse",
			X:          ev.X,
			Y:          ev.Y,
			Flags:      ev.Flags,
			WheelDelta: ev.WheelDelta,
			ElapsedNs:  ev.ElapsedNs,
		})
	}
	return nil, errUnknownRdpEventType
}
