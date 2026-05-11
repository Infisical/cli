//go:build rdp && (linux || darwin || windows)

package rdp

/*
#cgo CFLAGS: -I${SRCDIR}/native/include

#include <stdlib.h>
#include "rdp_bridge.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"
)

func (p *RDPProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	return p.handleConnectionWith(ctx, clientConn, func() (*Bridge, error) {
		return StartWithReadWriter(
			clientConn,
			p.config.TargetHost,
			p.config.TargetPort,
			p.config.InjectUsername,
			p.config.InjectPassword,
			p.config.InjectDomain,
		)
	})
}

// HandleConnectionRDCleanPath is the browser-flow variant (RDCleanPath instead of X.224).
func (p *RDPProxy) HandleConnectionRDCleanPath(ctx context.Context, clientConn net.Conn) error {
	return p.handleConnectionWith(ctx, clientConn, func() (*Bridge, error) {
		return StartRDCleanPathWithReadWriter(
			clientConn,
			p.config.TargetHost,
			p.config.TargetPort,
			p.config.InjectUsername,
			p.config.InjectPassword,
			p.config.InjectDomain,
			BrowserAcceptorUsername,
		)
	})
}

func (p *RDPProxy) handleConnectionWith(ctx context.Context, clientConn net.Conn, start func() (*Bridge, error)) error {
	defer clientConn.Close()
	if p.config.SessionLogger != nil {
		defer func() {
			_ = p.config.SessionLogger.Close()
		}()
	}

	bridge, err := start()
	if err != nil {
		return fmt.Errorf("rdp proxy: start bridge: %w", err)
	}
	defer bridge.Close()

	drainCtx, cancelDrain := context.WithCancel(ctx)
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		drainBridgeEvents(drainCtx, bridge, p.config.SessionLogger, p.config.SessionID, p.config.SessionStartedAt)
	}()
	// Let drain finish so recording tail isn't dropped; cancel paths bail early
	defer func() {
		select {
		case <-drainDone:
		case <-time.After(2 * pollTimeout):
		}
		cancelDrain()
	}()

	waitErr := make(chan error, 1)
	go func() { waitErr <- bridge.Wait() }()

	select {
	case err := <-waitErr:
		if err != nil && !errors.Is(err, ErrInvalidHandle) {
			cancelDrain()
			return fmt.Errorf("rdp proxy: session: %w", err)
		}
		return nil
	case <-ctx.Done():
		cancelDrain()
		_ = bridge.Cancel()
		<-waitErr
		return ctx.Err()
	}
}

// Wait blocks until the session ends. Idempotent.
func (b *Bridge) Wait() error {
	rc := C.rdp_bridge_wait(C.uint64_t(b.handle))
	switch rc {
	case C.RDP_BRIDGE_OK:
		return nil
	case C.RDP_BRIDGE_INVALID_HANDLE:
		return ErrInvalidHandle
	case C.RDP_BRIDGE_SESSION_ERROR, C.RDP_BRIDGE_THREAD_PANIC:
		return ErrSessionFailed
	default:
		return fmt.Errorf("rdp bridge: wait returned unexpected status %d", int32(rc))
	}
}

// Cancel is idempotent and safe from any goroutine.
func (b *Bridge) Cancel() error {
	rc := C.rdp_bridge_cancel(C.uint64_t(b.handle))
	if rc == C.RDP_BRIDGE_INVALID_HANDLE {
		return ErrInvalidHandle
	}
	return nil
}

// Close must be called after Wait has returned.
func (b *Bridge) Close() error {
	rc := C.rdp_bridge_free(C.uint64_t(b.handle))
	if b.cleanup != nil {
		b.cleanup()
	}
	if rc == C.RDP_BRIDGE_INVALID_HANDLE {
		return ErrInvalidHandle
	}
	return nil
}

// True when the real bridge is compiled in (vs the stub).
func IsSupported() bool { return true }

// PollEvent drains one tap event. Not safe to call concurrently for the same Bridge.
func (b *Bridge) PollEvent(timeout time.Duration) (PollResult, Event, error) {
	timeoutMs := timeout.Milliseconds()
	if timeoutMs < 0 {
		timeoutMs = 0
	}
	if timeoutMs > int64(^C.uint32_t(0)) {
		timeoutMs = int64(^C.uint32_t(0))
	}

	var raw C.struct_RdpEvent
	rc := C.rdp_bridge_poll_event(C.uint64_t(b.handle), &raw, C.uint32_t(timeoutMs))

	switch rc {
	case C.RDP_POLL_OK:
		// fall through to event materialization below
	case C.RDP_POLL_TIMEOUT:
		return PollTimeout, Event{}, nil
	case C.RDP_POLL_ENDED:
		return PollEnded, Event{}, nil
	case C.RDP_POLL_INVALID_HANDLE:
		return PollEnded, Event{}, ErrInvalidHandle
	default:
		return PollEnded, Event{}, fmt.Errorf("rdp bridge: poll returned unexpected status %d", int32(rc))
	}

	ev := Event{
		Type:       EventType(uint8(raw.event_type)),
		ElapsedNs:  uint64(raw.elapsed_ns),
		Flags:      uint32(raw.flags),
		WheelDelta: int32(raw.wheel_delta),
		Action:     Action(uint8(raw.action)),
	}
	switch ev.Type {
	case EventTypeKeyboard:
		ev.Scancode = uint8(raw.value_a)
	case EventTypeUnicode:
		ev.CodePoint = uint16(raw.value_a)
	case EventTypeMouse:
		ev.X = uint16(raw.value_a)
		ev.Y = uint16(raw.value_b)
	case EventTypeTargetFrame:
		// Ownership transferred from Rust; always free even if empty
		if raw.payload_ptr != nil {
			defer C.free(unsafe.Pointer(raw.payload_ptr))
			if raw.payload_len > 0 {
				ev.Payload = C.GoBytes(unsafe.Pointer(raw.payload_ptr), C.int(raw.payload_len))
			}
		}
	}

	return PollOK, ev, nil
}
