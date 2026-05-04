//go:build rdp && windows

package rdp

/*
#cgo CFLAGS: -I${SRCDIR}/native/include
#cgo windows LDFLAGS: -L${SRCDIR}/native/target/release -linfisical_rdp_bridge -lws2_32 -luserenv -lbcrypt -lntdll -ladvapi32 -lcrypt32 -lsecur32 -lwinpthread

#include "rdp_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func StartWithConn(conn net.Conn, targetHost string, targetPort uint16, username, password, acceptorUsername string) (*Bridge, error) {
	dupSocket, err := dupConnSocket(conn)
	if err != nil {
		return nil, fmt.Errorf("rdp bridge: dup client socket: %w", err)
	}
	return startWithDupedSocket(dupSocket, targetHost, targetPort, username, password, acceptorUsername)
}

func startWithDupedSocket(dupSocket windows.Handle, targetHost string, targetPort uint16, username, password, acceptorUsername string) (*Bridge, error) {
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
	cAcceptorUser := C.CString(acceptorUsername)
	defer C.free(unsafe.Pointer(cAcceptorUser))

	var handle C.uint64_t
	rc := C.rdp_bridge_start_windows_socket(
		C.uintptr_t(dupSocket),
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

	dupSocket, err := dupConnSocket(accepted)
	_ = accepted.Close()
	if err != nil {
		_ = peer.Close()
		return nil, fmt.Errorf("rdp bridge: dup accepted socket: %w", err)
	}

	bridge, err := startWithDupedSocket(dupSocket, targetHost, targetPort, username, password, acceptorUsername)
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

// DuplicateHandle (not WSADuplicateSocketW, which is for cross-process
// sharing): SOCKETs are kernel handles on modern Windows, so DuplicateHandle
// gives us an independent in-process SOCKET the bridge can own and close.
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
