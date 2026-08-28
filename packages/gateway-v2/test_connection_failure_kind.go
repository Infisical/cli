package gatewayv2

import (
	"errors"
	"io"
	"net"
	"os"
)

// Whether the target refused the credential or we never got far enough to ask. The control plane needs these
// apart: a refused credential stops the heartbeat schedule, while an unreachable target keeps retrying.
//
// A probe knows which of the two happened structurally, because it dials and then authenticates in that order,
// so the answer is recorded as the phases run rather than recovered afterwards from a driver's error text. That
// keeps a new account type from needing its own error codes here.
type testConnFailureKind string

const (
	failureKindAuth      testConnFailureKind = "auth"
	failureKindTransport testConnFailureKind = "transport"
	failureKindUnknown   testConnFailureKind = "unknown"
)

type probeError struct {
	kind testConnFailureKind
	err  error
}

func (e *probeError) Error() string { return e.err.Error() }
func (e *probeError) Unwrap() error { return e.err }

// connectFailure tags a failure that happened before the target could evaluate a credential.
func connectFailure(err error) error {
	if err == nil {
		return nil
	}
	return &probeError{kind: failureKindTransport, err: err}
}

// authFailure tags a failure from the step that authenticates. A network error this late means the connection
// died mid-exchange rather than the credential being refused, so it stays transport.
func authFailure(err error) error {
	if err == nil {
		return nil
	}
	if isNetworkError(err) {
		return &probeError{kind: failureKindTransport, err: err}
	}
	return &probeError{kind: failureKindAuth, err: err}
}

func isNetworkError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	// The peer closing mid-exchange is the connection dying, not a credential being turned down.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// An untagged failure is one no probe attributed to a phase, which the control plane treats as unclassified.
func classifyTestConnFailure(err error) testConnFailureKind {
	var probeErr *probeError
	if errors.As(err, &probeErr) {
		return probeErr.kind
	}
	return failureKindUnknown
}
