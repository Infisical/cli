//go:build rdp && (linux || darwin)

package rdp

/*
#cgo CFLAGS: -I${SRCDIR}/native/include
#cgo linux LDFLAGS: -L${SRCDIR}/native/target/release -linfisical_rdp_bridge -lm -ldl -lpthread
#cgo darwin LDFLAGS: -L${SRCDIR}/native/target/release -linfisical_rdp_bridge -framework Security -framework CoreFoundation -framework SystemConfiguration

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

// StartWithConn hands an independent dup of conn's fd to the bridge.
// For TLS-wrapped or otherwise non-fd-backed conns, use StartWithReadWriter.
func StartWithConn(conn net.Conn, targetHost string, targetPort uint16, username, password, acceptorUsername string) (*Bridge, error) {
	dupFd, err := dupConnFD(conn)
	if err != nil {
		return nil, fmt.Errorf("rdp bridge: dup client fd: %w", err)
	}
	return startWithDupedFD(dupFd, targetHost, targetPort, username, password, acceptorUsername)
}

// Ownership of dupFd transfers to Rust on success; we close it on failure.
func startWithDupedFD(dupFd int, targetHost string, targetPort uint16, username, password, acceptorUsername string) (*Bridge, error) {
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
	cAcceptorUser := C.CString(acceptorUsername)
	defer C.free(unsafe.Pointer(cAcceptorUser))

	var handle C.uint64_t
	rc := C.rdp_bridge_start_unix_fd(
		C.int(dupFd),
		cHost,
		C.uint16_t(targetPort),
		cUser,
		cPass,
		cAcceptorUser,
		&handle,
	)
	if rc != C.RDP_BRIDGE_OK {
		return nil, fmt.Errorf("rdp bridge: start failed (status %d)", int32(rc))
	}
	success = true
	return &Bridge{handle: uint64(handle)}, nil
}

// StartWithReadWriter adapts an fd-less Go byte stream (e.g. *tls.Conn
// from the gateway's mTLS-wrapped virtual connection) to the bridge,
// which needs a real file descriptor because the Rust side uses tokio's
// TcpStream::from_raw_fd and does direct async I/O on the socket.
//
// Trick: open a loopback TCP pair. Hand one end's fd to the bridge (it
// thinks it has a real client). Keep the other end in Go and shuttle
// bytes between it and rw with two io.Copy goroutines.
//
//	rw (e.g. *tls.Conn)  <-io.Copy->  peer  <-kernel loopback->  accepted (fd -> Rust bridge)
//
// Cost: two extra in-process copies and a loopback round-trip per byte.
// Negligible vs. the TLS + CredSSP work on either side.
func StartWithReadWriter(rw io.ReadWriter, targetHost string, targetPort uint16, username, password, acceptorUsername string) (*Bridge, error) {
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

	dupFd, err := dupConnFD(accepted)
	_ = accepted.Close()
	if err != nil {
		_ = peer.Close()
		return nil, fmt.Errorf("rdp bridge: dup accepted fd: %w", err)
	}

	bridge, err := startWithDupedFD(dupFd, targetHost, targetPort, username, password, acceptorUsername)
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
		p.config.AcceptorUsername,
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
