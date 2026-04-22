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
	"context"
	"errors"
	"fmt"
	"io"
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
// descriptor via syscall.Conn. For TLS-wrapped or otherwise non-fd-backed
// conns (like the ones the gateway receives), use [StartWithReadWriter]
// instead.
func StartWithConn(conn net.Conn, targetHost string, targetPort uint16, username, password string) (*Bridge, error) {
	dupFd, err := dupConnFD(conn)
	if err != nil {
		return nil, fmt.Errorf("rdp bridge: dup client fd: %w", err)
	}
	return startWithDupedFD(dupFd, targetHost, targetPort, username, password)
}

// startWithDupedFD hands ownership of `dupFd` to the Rust bridge. On
// success the bridge closes the fd when the session ends; on failure
// this function closes the fd itself before returning. Shared by
// StartWithConn and StartWithReadWriter.
func startWithDupedFD(dupFd int, targetHost string, targetPort uint16, username, password string) (*Bridge, error) {
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

// StartWithReadWriter starts a bridge session for a caller whose client
// stream is not fd-backed (e.g. *tls.Conn wrapping an mTLS'd virtual
// connection in the gateway). It creates a local loopback TCP pair, hands
// the kernel-backed accepted end to the Rust bridge, and pumps bytes
// between the other loopback end and the caller's `rw` via two io.Copy
// goroutines. The goroutines exit when either side closes; the bridge's
// Close method also tears them down.
//
// The caller retains ownership of `rw` and is responsible for closing it
// when done (the bridge does not close it).
func StartWithReadWriter(rw io.ReadWriter, targetHost string, targetPort uint16, username, password string) (*Bridge, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("rdp bridge: loopback listen: %w", err)
	}
	// We only ever accept one connection; close the listener either way.
	defer listener.Close()

	// Kick off the dial concurrently with accept. Either ordering would
	// work but the goroutine avoids a deadlock if some future net stack
	// decides accept must run first.
	type dialResult struct {
		conn net.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		c, err := net.Dial("tcp", listener.Addr().String())
		dialCh <- dialResult{c, err}
	}()

	accepted, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("rdp bridge: loopback accept: %w", err)
	}
	dr := <-dialCh
	if dr.err != nil {
		_ = accepted.Close()
		return nil, fmt.Errorf("rdp bridge: loopback dial: %w", dr.err)
	}
	peer := dr.conn

	// The accepted side gets handed to Rust. Dup its fd, then close our
	// copy so only Rust owns the socket going forward.
	dupFd, err := dupConnFD(accepted)
	_ = accepted.Close()
	if err != nil {
		_ = peer.Close()
		return nil, fmt.Errorf("rdp bridge: dup accepted fd: %w", err)
	}

	bridge, err := startWithDupedFD(dupFd, targetHost, targetPort, username, password)
	if err != nil {
		_ = peer.Close()
		return nil, err
	}

	// Pump bytes between the caller's rw and the loopback peer. Each
	// goroutine closes the peer on exit so the other side unblocks and
	// exits too, regardless of which half EOFs first.
	go func() {
		_, _ = io.Copy(peer, rw)
		_ = peer.Close()
	}()
	go func() {
		_, _ = io.Copy(rw, peer)
		_ = peer.Close()
	}()

	bridge.cleanup = func() { _ = peer.Close() }
	return bridge, nil
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

// HandleConnection is the entry point the gateway's PAM dispatcher calls
// for a Windows/RDP session. It takes ownership of `clientConn` (closes
// it on return), spawns a bridge via the loopback shim, and blocks until
// the session ends or `ctx` is cancelled (admin terminate, session
// expiry). On cancellation the bridge is signalled to abort and we wait
// for it to actually finish before returning `ctx.Err()`.
func (p *RDPProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	if p.config.SessionLogger != nil {
		defer func() {
			if err := p.config.SessionLogger.Close(); err != nil {
				// Don't fail the session on logger close error; it's a
				// best-effort flush of any buffered events.
				_ = err
			}
		}()
	}

	bridge, err := StartWithReadWriter(
		clientConn,
		p.config.TargetHost,
		p.config.TargetPort,
		p.config.InjectUsername,
		p.config.InjectPassword,
	)
	if err != nil {
		return fmt.Errorf("rdp proxy: start bridge: %w", err)
	}
	defer bridge.Close()

	// Run Wait on a goroutine so we can also select on ctx.Done().
	waitErr := make(chan error, 1)
	go func() { waitErr <- bridge.Wait() }()

	select {
	case err := <-waitErr:
		if err != nil && !errors.Is(err, ErrInvalidHandle) {
			return fmt.Errorf("rdp proxy: session: %w", err)
		}
		return nil
	case <-ctx.Done():
		_ = bridge.Cancel()
		<-waitErr // let the session unwind before we return
		return ctx.Err()
	}
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
