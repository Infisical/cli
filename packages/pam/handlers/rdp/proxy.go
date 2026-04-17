package rdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

// RDPProxyConfig holds configuration for the RDP proxy handler.
type RDPProxyConfig struct {
	TargetHost     string
	TargetPort     uint16
	InjectUsername string
	InjectPassword string
	SessionID      string
	SessionLogger  session.SessionLogger
}

// RDPProxy handles proxying RDP connections with credential injection.
// The real protocol work (acceptor + connector + event tap) lives in the
// native library wrapped by bridge.go; this type is glue between that
// library and Infisical's session framework.
type RDPProxy struct {
	config RDPProxyConfig
}

func NewRDPProxy(config RDPProxyConfig) *RDPProxy {
	return &RDPProxy{config: config}
}

// HandleConnection matches the signature used by the other PAM handlers.
// The gateway dispatcher hands us an already-TLS-terminated client conn;
// we take ownership, hand the underlying fd to the native bridge, and
// pump structured events into the session logger until the bridge ends.
func (p *RDPProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	sessionID := p.config.SessionID

	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().
		Str("sessionID", sessionID).
		Str("targetHost", p.config.TargetHost).
		Uint16("targetPort", p.config.TargetPort).
		Msg("New RDP connection for PAM session")

	bridge, err := StartWithConn(
		clientConn,
		p.config.TargetHost,
		p.config.TargetPort,
		p.config.InjectUsername,
		p.config.InjectPassword,
	)
	if err != nil {
		return fmt.Errorf("rdp: start bridge: %w", err)
	}
	defer bridge.Close()

	// Poll loop: drain events until the bridge ends or the context is
	// cancelled (session expiry / admin terminate).
	pollTimeoutMs := uint32(500)
	startedAt := time.Now()

	for {
		select {
		case <-ctx.Done():
			log.Info().Str("sessionID", sessionID).Msg("RDP session context cancelled")
			return ctx.Err()
		default:
		}

		ev, err := bridge.PollEvent(pollTimeoutMs)
		if err != nil {
			if errors.Is(err, ErrSessionEnded) {
				log.Info().Str("sessionID", sessionID).Msg("RDP bridge ended")
				return nil
			}
			if errors.Is(err, ErrInvalidHandle) {
				return nil
			}
			return fmt.Errorf("rdp: poll event: %w", err)
		}
		if ev == nil {
			continue // timed out; keep polling
		}

		if logErr := p.logEvent(startedAt, ev); logErr != nil {
			log.Error().
				Err(logErr).
				Str("sessionID", sessionID).
				Msg("Failed to log RDP event")
		}
	}
}

// recordedRDPEvent is the JSON shape we serialize into the session log.
// Phase 2 captures the structured fields that come across the FFI; Phase
// 3 will add the target frame payload for lossless bitmap recording.
type recordedRDPEvent struct {
	Type       string `json:"type"` // keyboard | unicode | mouse | target_frame
	ElapsedNS  uint64 `json:"elapsed_ns"`
	Scancode   uint32 `json:"scancode,omitempty"`
	CodePoint  uint32 `json:"code_point,omitempty"`
	X          uint32 `json:"x,omitempty"`
	Y          uint32 `json:"y,omitempty"`
	Flags      uint32 `json:"flags,omitempty"`
	WheelDelta int32  `json:"wheel_delta,omitempty"`
	FrameBytes uint32 `json:"frame_bytes,omitempty"`
	Action     string `json:"action,omitempty"` // x224 | fastpath
}

func (p *RDPProxy) logEvent(startedAt time.Time, ev *Event) error {
	rec := recordedRDPEvent{ElapsedNS: ev.ElapsedNS}
	var direction session.TerminalEventType

	switch ev.Type {
	case EventKeyboard:
		rec.Type = "keyboard"
		rec.Scancode = ev.ValueA
		rec.Flags = ev.Flags
		direction = session.TerminalEventInput
	case EventUnicode:
		rec.Type = "unicode"
		rec.CodePoint = ev.ValueA
		rec.Flags = ev.Flags
		direction = session.TerminalEventInput
	case EventMouse:
		rec.Type = "mouse"
		rec.X = ev.ValueA
		rec.Y = ev.ValueB
		rec.Flags = ev.Flags
		rec.WheelDelta = ev.WheelDelta
		direction = session.TerminalEventInput
	case EventTargetFrame:
		rec.Type = "target_frame"
		rec.FrameBytes = ev.ValueA
		if ev.Action == ActionFastPath {
			rec.Action = "fastpath"
		} else {
			rec.Action = "x224"
		}
		direction = session.TerminalEventOutput
	default:
		return fmt.Errorf("unknown rdp event type: %d", ev.Type)
	}

	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal rdp event: %w", err)
	}

	return p.config.SessionLogger.LogTerminalEvent(session.TerminalEvent{
		Timestamp:   time.Now(),
		EventType:   direction,
		ChannelType: session.TerminalChannelRDP,
		Data:        payload,
		ElapsedTime: time.Since(startedAt).Seconds(),
	})
}
