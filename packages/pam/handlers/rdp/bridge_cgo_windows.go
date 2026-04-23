//go:build rdp && windows

package rdp

/*
#cgo CFLAGS: -I${SRCDIR}/native/include
#cgo windows LDFLAGS: -L${SRCDIR}/native/target/release -linfisical_rdp_bridge -lws2_32 -luserenv -lbcrypt -lntdll -ladvapi32 -lcrypt32 -lsecur32

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

	"golang.org/x/sys/windows"
)

// StartWithConn starts a bridge session for the given TCP connection.
// Internally, an independent duplicate of the underlying SOCKET is
// handed to the bridge via DuplicateHandle; the caller's conn stays
// fully usable and is not closed by this function. The bridge closes
// its dup when the session ends.
//
// `conn` must be a *net.TCPConn or any net.Conn that exposes a raw
// socket via syscall.Conn. For TLS-wrapped or otherwise non-socket-backed
// conns (like the ones the gateway receives), use [StartWithReadWriter]
// instead.
func StartWithConn(conn net.Conn, targetHost string, targetPort uint16, username, password string) (*Bridge, error) {
	dupSocket, err := dupConnSocket(conn)
	if err != nil {
		return nil, fmt.Errorf("rdp bridge: dup client socket: %w", err)
	}
	return startWithDupedSocket(dupSocket, targetHost, targetPort, username, password)
}

// startWithDupedSocket hands ownership of `dupSocket` to the Rust bridge.
// On success the bridge closes the socket when the session ends; on
// failure this function closes the socket itself before returning.
// Shared by StartWithConn and StartWithReadWriter.
func startWithDupedSocket(dupSocket windows.Handle, targetHost string, targetPort uint16, username, password string) (*Bridge, error) {
	success := false
	defer func() {
		if !success {
			_ = windows.Closesocket(dupSocket)
		}
	}()

	cHost := C.CString(targetHost)
	defer C.free(unsafe.Pointer(cHost))
	cUser := C.CString(username)
	defer C.free(unsafe.Pointer(cUser))
	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cPass))

	var handle C.uint64_t
	rc := C.rdp_bridge_start_windows_socket(
		C.uintptr_t(dupSocket),
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
// stream is not socket-backed (e.g. *tls.Conn wrapping an mTLS'd virtual
// connection in the gateway). It creates a local loopback TCP pair,
// hands the kernel-backed accepted end to the Rust bridge, and pumps
// bytes between the other loopback end and the caller's `rw` via two
// io.Copy goroutines. The goroutines exit when either side closes; the
// bridge's Close method also tears them down.
//
// The caller retains ownership of `rw` and is responsible for closing
// it when done (the bridge does not close it).
func StartWithReadWriter(rw io.ReadWriter, targetHost string, targetPort uint16, username, password string) (*Bridge, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("rdp bridge: loopback listen: %w", err)
	}
	defer listener.Close()

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

	dupSocket, err := dupConnSocket(accepted)
	_ = accepted.Close()
	if err != nil {
		_ = peer.Close()
		return nil, fmt.Errorf("rdp bridge: dup accepted socket: %w", err)
	}

	bridge, err := startWithDupedSocket(dupSocket, targetHost, targetPort, username, password)
	if err != nil {
		_ = peer.Close()
		return nil, err
	}

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

// dupConnSocket returns a new SOCKET handle independent from `conn`'s
// internal one, using DuplicateHandle against the current process. The
// caller becomes responsible for closing the returned handle via
// windows.Closesocket. Requires `conn` to implement syscall.Conn.
//
// Note: this uses DuplicateHandle, not WSADuplicateSocketW.
// WSADuplicateSocketW is for cross-process socket sharing and requires
// the peer to call WSASocket with a WSAPROTOCOL_INFOW. For in-process
// SOCKET duplication, DuplicateHandle on the SOCKET's underlying kernel
// handle is the standard approach (SOCKETs are kernel handles on modern
// Windows).
func dupConnSocket(conn net.Conn) (windows.Handle, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("conn %T does not expose syscall.Conn", conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var dup windows.Handle
	var dupErr error
	proc := windows.CurrentProcess()
	ctrlErr := raw.Control(func(fd uintptr) {
		dupErr = windows.DuplicateHandle(
			proc,
			windows.Handle(fd),
			proc,
			&dup,
			0,
			false,
			windows.DUPLICATE_SAME_ACCESS,
		)
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	if dupErr != nil {
		return 0, dupErr
	}
	return dup, nil
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
		<-waitErr
		return ctx.Err()
	}
}
