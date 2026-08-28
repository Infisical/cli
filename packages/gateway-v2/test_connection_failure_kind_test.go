package gatewayv2

import (
	"errors"
	"fmt"
	"net"
	"testing"
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

// A credential is only offered once the transport handshake succeeded and the server accepted the method, so
// whether the client got that far is what separates a refused login from a handshake that never asked.
func TestSSHPhaseDependsOnCredentialBeingOffered(t *testing.T) {
	offered := false
	methods, err := buildSSHExecAuth(sshExecEnvelope{AuthMethod: "password", Password: "pw"}, func() { offered = true })
	if err != nil {
		t.Fatalf("buildSSHExecAuth: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected one auth method, got %d", len(methods))
	}
	if offered {
		t.Fatal("building the auth method must not count as offering a credential")
	}
}

func TestProbeErrorPreservesMessage(t *testing.T) {
	const message = "redis authentication failed: WRONGPASS"
	if got := authFailure(errors.New(message)).Error(); got != message {
		t.Fatalf("Error() = %q, want %q", got, message)
	}
}
