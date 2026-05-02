// Package rdp wraps the Rust MITM bridge behind the `rdp` build tag.
// Stub builds return ErrRdpUnavailable.
package rdp

import "errors"

var (
	ErrRdpUnavailable = errors.New("rdp bridge: not available in this build")
	ErrInvalidHandle  = errors.New("rdp bridge: invalid handle")
	ErrSessionFailed  = errors.New("rdp bridge: session ended with error")
)


type Bridge struct {
	handle  uint64
	cleanup func()
}
