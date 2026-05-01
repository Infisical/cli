// Package rdp wraps the Rust MITM bridge behind the `rdp` build tag.
// Stub builds return ErrRdpUnavailable.
package rdp

import "errors"

var (
	ErrRdpUnavailable = errors.New("rdp bridge: not available in this build")
	ErrInvalidHandle  = errors.New("rdp bridge: invalid handle")
	ErrSessionFailed  = errors.New("rdp bridge: session ended with error")
)

// Fixed placeholder credentials the RDP client presents to the acceptor
// side of the bridge. Must match ACCEPTOR_USERNAME / ACCEPTOR_PASSWORD in
// the Rust crate. Real authn happens upstream (Infisical + gateway).
const (
	AcceptorUsername = "infisical"
	AcceptorPassword = ""
)

type Bridge struct {
	handle  uint64
	cleanup func()
}
