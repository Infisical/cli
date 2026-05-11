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
	defer clientConn.Close()
	if p.config.SessionLogger != nil {
		defer func() {
			_ = p.config.SessionLogger.Close()
		}()
	}

	bridge, err := StartWithReadWriter(
		clientConn,
		p.config.TargetHost,
		p.config.TargetPort,
		p.config.InjectUsername,
		p.config.InjectPassword,
		p.config.InjectDomain,
	)
	if err != nil {
		return fmt.Errorf("rdp proxy: start bridge: %w", err)
	}
	defer bridge.Close()

	// Drain bridge tap events into the session logger. The Rust side closes
	// the events channel when the session ends, so the goroutine exits via
	// PollEnded without needing an explicit shutdown signal.
	drainCtx, cancelDrain := context.WithCancel(ctx)
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		drainBridgeEvents(drainCtx, bridge, p.config.SessionLogger, p.config.SessionID, p.config.PriorElapsedNs)
	}()
	// Wait for the drain to finish naturally on the normal-end path so the
	// tail of the recording isn't dropped: PollEnded fires after the Rust
	// side closes the events channel (post bridge.Wait return). Cancellation
	// paths trigger cancelDrain() explicitly below to bail early.
	defer func() {
		select {
		case <-drainDone:
		case <-time.After(2 * pollTimeout):
		}
		// Always release the drain context (no-op if already cancelled).
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

// Cancel is idempotent and safe from any goroutine, including
// concurrently with Wait.
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

// PollEvent drains one tap event with the given timeout. The returned Event
// is only meaningful when result == PollOK. PollEvent is not safe to call
// concurrently for the same Bridge; serialize calls in a single goroutine.
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
		// Always free the libc-malloc'd buffer Rust handed us, even if
		// the copy below is empty -- ownership transfer is unconditional.
		if raw.payload_ptr != nil {
			defer C.free(unsafe.Pointer(raw.payload_ptr))
			if raw.payload_len > 0 {
				ev.Payload = C.GoBytes(unsafe.Pointer(raw.payload_ptr), C.int(raw.payload_len))
			}
		}
	}

	return PollOK, ev, nil
}
