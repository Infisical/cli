// Package rdp wraps the Rust MITM bridge for Infisical's PAM Windows
// handler. The real implementation is gated behind the `rdp` build tag
// and a supported platform; other builds receive stubs that return
// [ErrRdpUnavailable] from every constructor.
package rdp

import "errors"

// ErrRdpUnavailable is returned by constructors when the RDP bridge is
// not compiled in (built without `-tags rdp`, or on a platform that
// does not yet ship the Rust static library).
var ErrRdpUnavailable = errors.New("rdp bridge: not available in this build")

// ErrInvalidHandle is returned when an operation references an unknown
// or already-freed bridge handle.
var ErrInvalidHandle = errors.New("rdp bridge: invalid handle")

// ErrSessionFailed is returned from Wait when the session ended with a
// handshake or forwarding error (rather than a clean client disconnect).
var ErrSessionFailed = errors.New("rdp bridge: session ended with error")

// Bridge owns the handle to a running RDP MITM session. Cancel may be
// called from any goroutine; Wait blocks until the session ends; Close
// releases the handle and must be called after Wait returns.
type Bridge struct {
	handle  uint64
	cleanup func() // runs during Close after the handle is freed; nil for direct fd sessions
}
