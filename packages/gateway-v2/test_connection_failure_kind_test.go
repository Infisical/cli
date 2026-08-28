package gatewayv2

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestClassifyTestConnFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want testConnFailureKind
	}{
		{
			name: "dial failure",
			err:  connectFailure(&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			want: failureKindTransport,
		},
		{
			name: "refused credential",
			err:  authFailure(errors.New("password authentication failed for user \"pam\"")),
			want: failureKindAuth,
		},
		{
			name: "connection dropped mid-authentication",
			err:  authFailure(&net.OpError{Op: "read", Err: errors.New("connection reset by peer")}),
			want: failureKindTransport,
		},
		{
			name: "wrapped by a caller",
			err:  fmt.Errorf("test connection: %w", authFailure(errors.New("login failed"))),
			want: failureKindAuth,
		},
		{
			name: "untagged",
			err:  errors.New("unsupported SQL dialect"),
			want: failureKindUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyTestConnFailure(tc.err); got != tc.want {
				t.Fatalf("classifyTestConnFailure() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The ssh package wraps both a refused credential and a failed handshake in "ssh: handshake failed", so only the
// nested ServerAuthError separates them.
func TestSSHFailurePhases(t *testing.T) {
	refused := fmt.Errorf("ssh: handshake failed: %w", &ssh.ServerAuthError{
		Errors: []error{errors.New("ssh: unable to authenticate")},
	})
	if got := classifyTestConnFailure(sshFailure(refused)); got != failureKindAuth {
		t.Fatalf("refused credential = %q, want %q", got, failureKindAuth)
	}

	kexMismatch := errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange")
	if got := classifyTestConnFailure(sshFailure(kexMismatch)); got != failureKindTransport {
		t.Fatalf("key exchange mismatch = %q, want %q", got, failureKindTransport)
	}
}

func TestProbeErrorPreservesMessage(t *testing.T) {
	const message = "redis authentication failed: WRONGPASS"
	if got := authFailure(errors.New(message)).Error(); got != message {
		t.Fatalf("Error() = %q, want %q", got, message)
	}
}
