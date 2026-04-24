//go:build rdp && (linux || darwin || windows)

package rdp

/*
#cgo CFLAGS: -I${SRCDIR}/native/include

#include "rdp_bridge.h"
*/
import "C"

import "fmt"

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

// IsSupported reports whether this build has a real RDP bridge. Used
// by the gateway to decide whether to advertise RDP in the capabilities
// response: a stub-build gateway that advertises support would route
// RDP sessions only to fail them at connect time.
func IsSupported() bool { return true }
