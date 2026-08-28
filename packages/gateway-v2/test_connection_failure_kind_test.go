package gatewayv2

import (
	"errors"
	"testing"
)

func TestClassifySSHHandshakeFailures(t *testing.T) {
	cases := []struct {
		name string
		err  string
		want testConnFailureKind
	}{
		{
			name: "rejected password",
			err:  "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain",
			want: failureKindAuth,
		},
		{
			name: "no common key exchange algorithm",
			err:  "ssh: handshake failed: ssh: no common algorithm for key exchange; client offered: [...], server offered: [...]",
			want: failureKindTransport,
		},
		{
			name: "peer hung up mid handshake",
			err:  "ssh: handshake failed: read tcp 10.0.0.1:22: connection reset by peer",
			want: failureKindTransport,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyTestConnFailure(errors.New(tc.err)); got != tc.want {
				t.Fatalf("classifyTestConnFailure(%q) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
