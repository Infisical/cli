//go:build !rdp || (!linux && !darwin && !windows)

package rdp

import (
	"context"
	"io"
	"net"
)

// Stub implementations for builds without `-tags rdp` or on platforms
// where the Rust bridge isn't compiled. All entry points return
// ErrRdpUnavailable.

func StartWithConn(_ net.Conn, _ string, _ uint16, _, _, _ string) (*Bridge, error) {
	return nil, ErrRdpUnavailable
}

func StartWithReadWriter(_ io.ReadWriter, _ string, _ uint16, _, _, _ string) (*Bridge, error) {
	return nil, ErrRdpUnavailable
}

func (p *RDPProxy) HandleConnection(_ context.Context, clientConn net.Conn) error {
	_ = clientConn.Close()
	return ErrRdpUnavailable
}

func (b *Bridge) Wait() error   { return ErrRdpUnavailable }
func (b *Bridge) Cancel() error { return ErrRdpUnavailable }
func (b *Bridge) Close() error  { return ErrRdpUnavailable }

// IsSupported reports whether this build has a real RDP bridge. See the
// rdp-enabled counterpart in bridge_cgo_shared.go for details.
func IsSupported() bool { return false }
