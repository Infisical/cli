package gatewayv2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The backend builds this request in TypeScript, so nothing checks the field names match at compile time.
// These payloads were captured from buildGatewayConnectionTest itself.
func TestClickhouseTestParamsContract(t *testing.T) {
	cases := []struct {
		name           string
		payload        string
		wantHTTPPort   int
		wantNativePort int
		wantSSL        bool
	}{
		{
			name:           "both interfaces",
			payload:        `{"mode":"clickhouse","username":"default","password":"pw","database":"analytics","httpPort":8123,"nativePort":9000,"sslEnabled":false,"sslRejectUnauthorized":true}`,
			wantHTTPPort:   8123,
			wantNativePort: 9000,
		},
		{
			name:           "native only",
			payload:        `{"mode":"clickhouse","username":"default","password":"pw","database":"analytics","nativePort":9440,"sslEnabled":true,"sslRejectUnauthorized":true}`,
			wantHTTPPort:   0,
			wantNativePort: 9440,
			wantSSL:        true,
		},
		{
			name:           "http only",
			payload:        `{"mode":"clickhouse","username":"default","password":"pw","database":"analytics","httpPort":8443,"sslEnabled":true,"sslRejectUnauthorized":false}`,
			wantHTTPPort:   8443,
			wantNativePort: 0,
			wantSSL:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var params clickhouseTestParams
			require.NoError(t, json.Unmarshal([]byte(tc.payload), &params))

			require.Equal(t, tc.wantHTTPPort, params.HttpPort)
			require.Equal(t, tc.wantNativePort, params.NativePort)
			require.Equal(t, "default", params.Username)
			require.Equal(t, "analytics", params.Database)
			require.Equal(t, "pw", params.Password)
			// A rename here would decode as false and quietly disable TLS for the probe.
			require.Equal(t, tc.wantSSL, params.SslEnabled)
			require.NotNil(t, params.SslRejectUnauthorized)
		})
	}
}

// The ports to probe come from the request body, so the signed certificate is what stops a caller pointing
// the gateway at a port the platform never authorised.
func TestRPCTargetAllows(t *testing.T) {
	t.Run("a certificate naming one port authorises only that port", func(t *testing.T) {
		target := rpcTarget{host: "db.internal", port: 8123}
		require.True(t, target.allows(8123))
		require.False(t, target.allows(9000))
		require.False(t, target.allows(22))
	})

	t.Run("a certificate naming several authorises each of them", func(t *testing.T) {
		target := rpcTarget{host: "db.internal", port: 8123, ports: []int{8123, 9000}}
		require.True(t, target.allows(8123))
		require.True(t, target.allows(9000))
		require.False(t, target.allows(22), "a port outside the certificate stays refused")
	})
}
