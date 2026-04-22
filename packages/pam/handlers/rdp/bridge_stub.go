//go:build !rdp || (!linux && !darwin)

package rdp

import "net"

// StartWithConn is a stub that reports the RDP bridge is unavailable in
// this build. To enable the real implementation, build with `-tags rdp`
// on a supported platform (linux, darwin; windows and others land in
// later phases).
func StartWithConn(_ net.Conn, _ string, _ uint16, _, _ string) (*Bridge, error) {
	return nil, ErrRdpUnavailable
}

// Wait is a stub for builds without the RDP bridge.
func (b *Bridge) Wait() error { return ErrRdpUnavailable }

// Cancel is a stub for builds without the RDP bridge.
func (b *Bridge) Cancel() error { return ErrRdpUnavailable }

// Close is a stub for builds without the RDP bridge.
func (b *Bridge) Close() error { return ErrRdpUnavailable }
