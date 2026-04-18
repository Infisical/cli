// Package rdp wraps the native RDP bridge (Rust, via CGo) for the gateway.
//
// Phase 1 Step 2: thin CGo wrapper exposing an idiomatic Go interface over
// the handle-based C ABI defined in native/include/rdp_bridge.h.
//
// The Rust static library is expected at
//   packages/pam/handlers/rdp/native/target/release/libinfisical_rdp_bridge.a
// Running `go generate ./packages/pam/handlers/rdp/...` invokes cargo to
// produce it. CI / release hooks should do the same before `go build`.

//go:generate bash -c "cd native && cargo build --release"
package rdp

/*
#cgo CFLAGS: -I${SRCDIR}/native/include
#cgo darwin LDFLAGS: -L${SRCDIR}/native/target/release -linfisical_rdp_bridge -framework Security -framework CoreFoundation -framework SystemConfiguration
#cgo linux LDFLAGS:  -L${SRCDIR}/native/target/release -linfisical_rdp_bridge -lm -ldl -lpthread

#include "rdp_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"unsafe"
)

// EventType discriminates which fields of Event are meaningful.
type EventType uint8

const (
	EventKeyboard    EventType = C.RDP_EVT_KEYBOARD
	EventUnicode     EventType = C.RDP_EVT_UNICODE
	EventMouse       EventType = C.RDP_EVT_MOUSE
	EventTargetFrame EventType = C.RDP_EVT_TARGET_FRAME
)

// FrameAction indicates which RDP transport a TargetFrame event came in on.
type FrameAction uint8

const (
	ActionX224     FrameAction = C.RDP_ACTION_X224
	ActionFastPath FrameAction = C.RDP_ACTION_FASTPATH
)

// Event is the structured session event produced by the native bridge.
// Field meaning depends on Type; see rdp_bridge.h for semantics.
type Event struct {
	Type       EventType
	ElapsedNS  uint64
	ValueA     uint32
	ValueB     uint32
	Flags      uint32
	WheelDelta int32
	Action     FrameAction
}

// Bridge is a handle to an active MITM session running in the native
// library. Obtain one via Start. Always call Close when done.
type Bridge struct {
	handle C.uint64_t
}

// Start kicks off a bridge that will listen on listenAddr, accept ONE
// inbound RDP connection, and proxy it to target:port injecting the
// provided credentials. Returns immediately; the bridge runs in a
// background thread inside the Rust library.
func Start(targetHost string, targetPort uint16, username, password, listenAddr string) (*Bridge, error) {
	cTarget := C.CString(targetHost)
	defer C.free(unsafe.Pointer(cTarget))
	cUser := C.CString(username)
	defer C.free(unsafe.Pointer(cUser))
	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cPass))
	cListen := C.CString(listenAddr)
	defer C.free(unsafe.Pointer(cListen))

	h := C.rdp_bridge_start(cTarget, C.uint16_t(targetPort), cUser, cPass, cListen)
	if h == 0 {
		return nil, errors.New("rdp_bridge_start failed (invalid args)")
	}
	return &Bridge{handle: h}, nil
}

// StartWithConn kicks off a bridge that consumes an already-accepted
// client connection such as the *tls.Conn the gateway hands to PAM
// handlers.
//
// The native bridge needs a raw TCP file descriptor, but the gateway's
// socket is often wrapped in TLS (or some other protocol) that lives
// only in Go. To bridge the gap we open a local loopback TCP pair:
//
//   Rust bridge  <--TCP-->  Go loopback conn  <--io.Copy-->  clientConn
//
// Rust owns one half (the dialed end); Go copies bytes between the
// other half and the caller's connection. The caller keeps ownership
// of clientConn and should Close it when done with the session.
func StartWithConn(clientConn net.Conn, targetHost string, targetPort uint16, username, password string) (*Bridge, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("rdp: loopback listen: %w", err)
	}
	defer listener.Close()

	acceptCh := make(chan net.Conn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptErrCh <- acceptErr
			return
		}
		acceptCh <- conn
	}()

	// Dial our own listener; the dialed end's fd goes to Rust.
	dialed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("rdp: loopback dial: %w", err)
	}
	dialedTcp, ok := dialed.(*net.TCPConn)
	if !ok {
		dialed.Close()
		return nil, fmt.Errorf("rdp: dialed non-TCPConn %T", dialed)
	}

	var loopbackPeer net.Conn
	select {
	case loopbackPeer = <-acceptCh:
	case err = <-acceptErrCh:
		dialedTcp.Close()
		return nil, fmt.Errorf("rdp: loopback accept: %w", err)
	}

	// Dup the dialed fd; hand the copy to Rust so we can close our end
	// independently when the session ends.
	rawConn, err := dialedTcp.SyscallConn()
	if err != nil {
		dialedTcp.Close()
		loopbackPeer.Close()
		return nil, fmt.Errorf("rdp: SyscallConn: %w", err)
	}
	var dupFd int
	var dupErr error
	if ctrlErr := rawConn.Control(func(fd uintptr) {
		dupFd, dupErr = syscall.Dup(int(fd))
	}); ctrlErr != nil {
		dialedTcp.Close()
		loopbackPeer.Close()
		return nil, fmt.Errorf("rdp: Control: %w", ctrlErr)
	}
	if dupErr != nil {
		dialedTcp.Close()
		loopbackPeer.Close()
		return nil, fmt.Errorf("rdp: dup fd: %w", dupErr)
	}
	// Go closes its copy of the fd — Rust owns the dup.
	dialedTcp.Close()

	cTarget := C.CString(targetHost)
	defer C.free(unsafe.Pointer(cTarget))
	cUser := C.CString(username)
	defer C.free(unsafe.Pointer(cUser))
	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cPass))

	h := C.rdp_bridge_start_with_fd(
		C.int(dupFd),
		cTarget,
		C.uint16_t(targetPort),
		cUser,
		cPass,
	)
	if h == 0 {
		_ = syscall.Close(dupFd)
		loopbackPeer.Close()
		return nil, errors.New("rdp_bridge_start_with_fd failed")
	}

	// Shuttle bytes between the loopback and the caller's connection.
	// When either side closes, the other's io.Copy returns and the
	// peer conn is closed, tearing the bridge down cleanly.
	go func() {
		defer loopbackPeer.Close()
		_, _ = io.Copy(loopbackPeer, clientConn)
	}()
	go func() {
		_, _ = io.Copy(clientConn, loopbackPeer)
	}()

	return &Bridge{handle: h}, nil
}

// PollEvent blocks up to timeoutMs for the next session event.
//
// Returns:
//
//	(*Event, nil)  -- event available
//	(nil, nil)     -- timed out; try again
//	(nil, io.EOF equivalent) -- session ended; stop polling
func (b *Bridge) PollEvent(timeoutMs uint32) (*Event, error) {
	var raw C.rdp_event_t
	rc := C.rdp_bridge_poll_event(b.handle, &raw, C.uint32_t(timeoutMs))
	switch int32(rc) {
	case C.RDP_POLL_OK:
		return &Event{
			Type:       EventType(raw.event_type),
			ElapsedNS:  uint64(raw.elapsed_ns),
			ValueA:     uint32(raw.value_a),
			ValueB:     uint32(raw.value_b),
			Flags:      uint32(raw.flags),
			WheelDelta: int32(raw.wheel_delta),
			Action:     FrameAction(raw.action),
		}, nil
	case C.RDP_POLL_TIMEOUT:
		return nil, nil
	case C.RDP_POLL_ENDED:
		return nil, ErrSessionEnded
	case C.RDP_POLL_INVALID_HANDLE:
		return nil, ErrInvalidHandle
	default:
		return nil, fmt.Errorf("rdp_bridge_poll_event: unexpected rc=%d", int32(rc))
	}
}

// Close tears down the bridge and releases its resources.
// Safe to call once per Bridge.
func (b *Bridge) Close() error {
	rc := C.rdp_bridge_close(b.handle)
	if int32(rc) != 0 {
		return ErrInvalidHandle
	}
	return nil
}

// ErrSessionEnded is returned by PollEvent when the bridge has shut down.
var ErrSessionEnded = errors.New("rdp session ended")

// ErrInvalidHandle is returned when a bridge handle is unknown or closed.
var ErrInvalidHandle = errors.New("rdp: invalid bridge handle")
