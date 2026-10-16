package browser

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCredentialHeaders(t *testing.T) {
	cases := []struct {
		name   string
		config BrowserProxyConfig
		want   map[string]string
	}{
		{"none", BrowserProxyConfig{AuthMethod: AuthMethodNone}, nil},
		{"basic", BrowserProxyConfig{AuthMethod: AuthMethodBasic, Username: "alice", Password: "s3cret"}, map[string]string{"Authorization": "Basic YWxpY2U6czNjcmV0"}},
		{"bearer", BrowserProxyConfig{AuthMethod: AuthMethodBearer, Token: "tok"}, map[string]string{"Authorization": "Bearer tok"}},
		{"header", BrowserProxyConfig{AuthMethod: AuthMethodHeader, HeaderName: "X-Api-Key", HeaderValue: "key"}, map[string]string{"X-Api-Key": "key"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			headers, err := credentialHeaders(c.config)
			require.NoError(t, err)
			require.Equal(t, c.want, headers)
		})
	}

	t.Run("an unknown method is refused", func(t *testing.T) {
		_, err := credentialHeaders(BrowserProxyConfig{AuthMethod: "cookie"})
		require.ErrorContains(t, err, "unsupported")
	})
	t.Run("a header name outside the platform's rule is refused", func(t *testing.T) {
		_, err := credentialHeaders(BrowserProxyConfig{AuthMethod: AuthMethodHeader, HeaderName: "X-Key: injected", HeaderValue: "key"})
		require.Error(t, err)
	})
	t.Run("a line break in a value is refused", func(t *testing.T) {
		_, err := credentialHeaders(BrowserProxyConfig{AuthMethod: AuthMethodBearer, Token: "tok\r\nX-Other: 1"})
		require.Error(t, err)
	})
}

func TestResolveStartPath(t *testing.T) {
	appURL, err := url.Parse("http://app.internal:3000/base")
	require.NoError(t, err)

	got, err := resolveStartPath(appURL, "")
	require.NoError(t, err)
	require.Equal(t, "http://app.internal:3000/base", got)

	got, err = resolveStartPath(appURL, "/dashboard?tab=1")
	require.NoError(t, err)
	require.Equal(t, "http://app.internal:3000/dashboard?tab=1", got)

	for _, offHost := range []string{"//evil.example/x", "https://evil.example/", "relative"} {
		_, err := resolveStartPath(appURL, offHost)
		require.Error(t, err, offHost)
	}
}

func TestOriginFillsDefaultPorts(t *testing.T) {
	require.Equal(t, Origin("https://App.Internal/x"), Origin("https://app.internal:443/y"))
	require.NotEqual(t, Origin("http://app.internal"), Origin("https://app.internal"))
	require.NotEqual(t, Origin("https://app.internal"), Origin("https://app.internal:8443"))
}

func TestRequestAllowed(t *testing.T) {
	require.True(t, RequestAllowed("https://app.internal/page", "app.internal"))
	require.True(t, RequestAllowed("http://APP.internal:8080/other-port", "app.internal"))
	require.True(t, RequestAllowed("wss://app.internal/socket", "app.internal"))
	require.True(t, RequestAllowed("data:image/png;base64,AAAA", "app.internal"))
	require.True(t, RequestAllowed("blob:https://app.internal/1234", "app.internal"))

	require.False(t, RequestAllowed("https://other.internal/", "app.internal"))
	require.False(t, RequestAllowed("https://app.internal.evil.example/", "app.internal"))
	require.False(t, RequestAllowed("file:///etc/passwd", "app.internal"))
}
