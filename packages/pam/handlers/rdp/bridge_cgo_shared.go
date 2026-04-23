//go:build rdp && (linux || darwin || windows)

package rdp

/*
#cgo CFLAGS: -I${SRCDIR}/native/include

#include "rdp_bridge.h"
*/
import "C"

import "fmt"

// Wait blocks until the session ends. Returns nil on a clean end
// (including the client hard-closing the TCP connection after a normal
// session), [ErrSessionFailed] on handshake or forwarding failure, or
// [ErrInvalidHandle] if the handle is unknown. Calling Wait a second
// time on the same handle returns nil (the session is already done).
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

// Cancel signals the session to stop. Idempotent; safe from any
// goroutine even while another goroutine is inside Wait.
func (b *Bridge) Cancel() error {
	rc := C.rdp_bridge_cancel(C.uint64_t(b.handle))
	if rc == C.RDP_BRIDGE_INVALID_HANDLE {
		return ErrInvalidHandle
	}
	return nil
}

// Close releases the bridge handle. Call after Wait has returned. If the
// bridge was created with a loopback shim (via StartWithReadWriter),
// Close also tears down the shim goroutines by closing their loopback
// endpoint.
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
