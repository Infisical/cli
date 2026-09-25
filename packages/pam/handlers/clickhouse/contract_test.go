package clickhouse

import (
	"encoding/json"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/stretchr/testify/require"
)

// The API and the gateway agree on these shapes only by convention, and a renamed field would not fail to...
func TestSessionCredentialsContract(t *testing.T) {
	cases := []struct {
		name                   string
		payload                string
		wantPort               int
		wantNativePort         int
		wantSSL                bool
		wantRejectUnauthorized bool
	}{
		{
			name:                   "both interfaces",
			payload:                `{"host":"ch.example.com","port":8123,"nativePort":9000,"database":"analytics","sslEnabled":false,"sslRejectUnauthorized":true,"username":"default","password":"pw"}`,
			wantPort:               8123,
			wantNativePort:         9000,
			wantRejectUnauthorized: true,
		},
		{
			name:                   "native only, so no HTTP port is sent at all",
			payload:                `{"host":"ch.example.com","nativePort":9440,"database":"analytics","sslEnabled":true,"sslRejectUnauthorized":true,"username":"default","password":"pw"}`,
			wantPort:               0,
			wantNativePort:         9440,
			wantSSL:                true,
			wantRejectUnauthorized: true,
		},
		{
			name:           "http only, so no native port is sent at all",
			payload:        `{"host":"ch.example.com","port":8443,"database":"analytics","sslEnabled":true,"sslRejectUnauthorized":false,"username":"default","password":"pw"}`,
			wantPort:       8443,
			wantNativePort: 0,
			wantSSL:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var credentials api.PAMSessionCredentials
			require.NoError(t, json.Unmarshal([]byte(tc.payload), &credentials))

			require.Equal(t, tc.wantPort, credentials.Port)
			require.Equal(t, tc.wantNativePort, credentials.NativePort)
			require.Equal(t, "ch.example.com", credentials.Host)
			require.Equal(t, "default", credentials.Username)
			require.Equal(t, "pw", credentials.Password)
			// A rename here would decode as false, silently dropping TLS and sending the password in clear.
			require.Equal(t, tc.wantSSL, credentials.SSLEnabled)
			require.Equal(t, tc.wantRejectUnauthorized, credentials.SSLRejectUnauthorized)
		})
	}
}
