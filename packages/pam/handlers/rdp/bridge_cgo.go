//go:build rdp && (linux || darwin)

package rdp

/*
#cgo CFLAGS: -I${SRCDIR}/native/include
#cgo linux LDFLAGS: -L${SRCDIR}/native/target/release -linfisical_rdp_bridge -lm -ldl -lpthread -lz
#cgo darwin LDFLAGS: -L${SRCDIR}/native/target/release -linfisical_rdp_bridge -lz -framework Security -framework CoreFoundation -framework SystemConfiguration

#include "rdp_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// StartWithConn starts a bridge session for the given TCP connection.
// Internally, an independent dup of the underlying file descriptor is
// handed to the bridge; the caller's conn stays fully usable and is not
// closed by this function. The bridge closes its dup when the session
// ends.
//
// `conn` must be a *net.TCPConn or any net.Conn that exposes a raw file
// descriptor via syscall.Conn. Passing a TLS-wrapped conn will fail;
// Phase 3 will introduce a loopback shim for that case.
func StartWithConn(conn net.Conn, targetHost string, targetPort uint16, username, password string) (*Bridge, error) {
	dupFd, err := dupConnFD(conn)
	if err != nil {
		return nil, fmt.Errorf("rdp bridge: dup client fd: %w", err)
	}
	// If the start call fails below, we still own the dup; close it.
	success := false
	defer func() {
		if !success {
			_ = syscall.Close(dupFd)
		}
	}()

	cHost := C.CString(targetHost)
	defer C.free(unsafe.Pointer(cHost))
	cUser := C.CString(username)
	defer C.free(unsafe.Pointer(cUser))
	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cPass))

	var handle C.uint64_t
	rc := C.rdp_bridge_start_unix_fd(
		C.int(dupFd),
		cHost,
		C.uint16_t(targetPort),
		cUser,
		cPass,
		&handle,
	)
	if rc != C.RDP_BRIDGE_OK {
		return nil, fmt.Errorf("rdp bridge: start failed (status %d)", int32(rc))
	}
	success = true
	return &Bridge{handle: uint64(handle)}, nil
}

// dupConnFD returns a new file descriptor independent from `conn`'s
// internal one. The caller becomes responsible for closing the returned
// fd. Requires `conn` to implement syscall.Conn.
func dupConnFD(conn net.Conn) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return -1, fmt.Errorf("conn %T does not expose syscall.Conn", conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var dup int
	var dupErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		dup, dupErr = syscall.Dup(int(fd))
	})
	if ctrlErr != nil {
		return -1, ctrlErr
	}
	if dupErr != nil {
		return -1, dupErr
	}
	return dup, nil
}

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

// Close releases the bridge handle. Call after Wait has returned.
func (b *Bridge) Close() error {
	rc := C.rdp_bridge_free(C.uint64_t(b.handle))
	if rc == C.RDP_BRIDGE_INVALID_HANDLE {
		return ErrInvalidHandle
	}
	return nil
}
