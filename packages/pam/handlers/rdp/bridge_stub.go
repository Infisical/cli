//go:build !rdp || (!linux && !darwin && !windows)

package rdp

import (
	"context"
	"io"
	"net"
)

// StartWithConn is a stub that reports the RDP bridge is unavailable in
// this build. To enable the real implementation, build with `-tags rdp`
// on a supported platform (linux, darwin, windows).
func StartWithConn(_ net.Conn, _ string, _ uint16, _, _ string) (*Bridge, error) {
	return nil, ErrRdpUnavailable
}

// StartWithReadWriter is a stub for builds without the RDP bridge.
func StartWithReadWriter(_ io.ReadWriter, _ string, _ uint16, _, _ string) (*Bridge, error) {
	return nil, ErrRdpUnavailable
}

// HandleConnection is a stub for builds without the RDP bridge. The
// gateway dispatcher calls into this on an RDP session; returning
// ErrRdpUnavailable surfaces a clean "this gateway build does not
// support RDP" error to the caller.
func (p *RDPProxy) HandleConnection(_ context.Context, clientConn net.Conn) error {
	_ = clientConn.Close()
	return ErrRdpUnavailable
}

// Wait is a stub for builds without the RDP bridge.
func (b *Bridge) Wait() error { return ErrRdpUnavailable }

// Cancel is a stub for builds without the RDP bridge.
func (b *Bridge) Cancel() error { return ErrRdpUnavailable }

// Close is a stub for builds without the RDP bridge.
func (b *Bridge) Close() error { return ErrRdpUnavailable }
