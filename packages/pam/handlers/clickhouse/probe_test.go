package clickhouse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProbeNativeProtocolAcceptsAnyNativeAnswerAndSendsNoCredential(t *testing.T) {
	t.Run("a refused login still proves the port", func(t *testing.T) {
		upstream := startFakeClickHouse(t)
		upstream.refuseWith = "Authentication failed"

		require.NoError(t, ProbeNativeProtocol(t.Context(), ClickHouseProxyConfig{
			NativeAddr: upstream.addr(),
			Username:   "account",
			Password:   "stored-password",
		}))

		require.Eventually(t, func() bool {
			hello, _, _, _ := upstream.snapshot()
			return hello.Name != ""
		}, 5*time.Second, 20*time.Millisecond)
		hello, _, _, _ := upstream.snapshot()
		require.Empty(t, hello.User)
		require.Empty(t, hello.Password)
	})

	t.Run("an http port is named", func(t *testing.T) {
		err := ProbeNativeProtocol(t.Context(), ClickHouseProxyConfig{NativeAddr: startHTTPResponder(t)})
		require.ErrorContains(t, err, "looks like ClickHouse's HTTP port")
	})
}

func TestProbeHTTPInterface(t *testing.T) {
	t.Run("clickhouse's ping answer proves the port", func(t *testing.T) {
		var sawCredential bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawCredential = r.Header.Get("X-ClickHouse-Key") != "" || r.URL.Query().Has("password")
			if r.URL.Path == "/ping" {
				_, _ = w.Write([]byte("Ok.\n"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(server.Close)

		require.NoError(t, ProbeHTTPInterface(t.Context(), ClickHouseProxyConfig{
			TargetAddr: strings.TrimPrefix(server.URL, "http://"),
			Password:   "stored-password",
		}))
		require.False(t, sawCredential)
	})

	t.Run("another http server is refused", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(server.Close)

		err := ProbeHTTPInterface(t.Context(), ClickHouseProxyConfig{TargetAddr: strings.TrimPrefix(server.URL, "http://")})
		require.ErrorContains(t, err, "not as ClickHouse's HTTP interface")
	})

	t.Run("the native port entered as the http one fails", func(t *testing.T) {
		upstream := startFakeClickHouse(t)
		require.Error(t, ProbeHTTPInterface(t.Context(), ClickHouseProxyConfig{TargetAddr: upstream.addr()}))
	})
}

// The port under test is the one the signed certificate authorised, so a redirect must not take the
// probe to an address nobody authorised.
func TestConnectionProbesRefuseARedirect(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Ok.\n"))
	}))
	t.Cleanup(elsewhere.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	addr := strings.TrimPrefix(redirector.URL, "http://")
	for name, probe := range map[string]func() error{
		"the interface probe": func() error {
			return ProbeHTTPInterface(t.Context(), ClickHouseProxyConfig{TargetAddr: addr})
		},
		"the credential test": func() error {
			return TestConnection(t.Context(), ClickHouseProxyConfig{TargetAddr: addr, Username: "account"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := probe()
			require.ErrorContains(t, err, "redirected")
		})
	}
}
