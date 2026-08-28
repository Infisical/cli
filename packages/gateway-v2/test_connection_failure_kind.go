package gatewayv2

import (
	"errors"
	"io"
	"net"
	"os"
)

// A refused credential stops the heartbeat schedule; an unreachable target keeps retrying. Probes dial and then
// authenticate, so each tags the phase it failed in rather than the classification being read back out of the
// driver's error text, which would need new codes for every account type.
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

func connectFailure(err error) error {
	if err == nil {
		return nil
	}
	return &probeError{kind: failureKindTransport, err: err}
}

// A network error at this point is the connection dying mid-exchange, not the credential being refused.
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
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

func classifyTestConnFailure(err error) testConnFailureKind {
	var probeErr *probeError
	if errors.As(err, &probeErr) {
		return probeErr.kind
	}
	return failureKindUnknown
}
