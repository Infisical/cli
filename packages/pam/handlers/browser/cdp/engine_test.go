package cdp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/browser"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
)

func TestSessionInjectsCredentialAndBlocksOtherHosts(t *testing.T) {
	binary := browser.BinaryPath()
	if binary == "" {
		t.Skipf("no browser binary found; set %s to run this test", browser.BinaryEnvName)
	}

	// Both resolve to loopback, but localhost is a different host from 127.0.0.1.
	var otherHostHits atomic.Int32
	otherHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHostHits.Add(1)
	}))
	defer otherHost.Close()
	otherHostURL := strings.Replace(otherHost.URL, "127.0.0.1", "localhost", 1)

	sideDoorAuth := make(chan string, 1)
	sideDoor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sideDoorAuth <- r.Header.Get("Authorization"):
		default:
		}
	}))
	defer sideDoor.Close()

	var sawToken, sawCookie atomic.Bool
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/":
			sawToken.Store(true)
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s1"})
			fmt.Fprintf(w, `<html><head><title>Web app test</title></head><body>
<img src="/cookie-check">
<img src="%s/pixel">
<img src="%s/pixel">
</body></html>`, sideDoor.URL, otherHostURL)
		case "/cookie-check":
			if cookie, err := r.Cookie("sid"); err == nil && cookie.Value == "s1" {
				sawCookie.Store(true)
			}
		}
	}))
	defer app.Close()

	pool := NewPool(NewExecLauncher(ExecLauncherConfig{
		BinaryPath:  binary,
		ProfileRoot: t.TempDir(),
		NoSandbox:   os.Geteuid() == 0,
	}), PoolConfig{})
	defer pool.Close()

	s, _, err := browser.StartSession(t.Context(), NewEngine(pool), browser.BrowserProxyConfig{
		SessionID:             "test-session",
		TargetURL:             app.URL,
		AuthMethod:            browser.AuthMethodBearer,
		Token:                 "test-token",
		TLSRejectUnauthorized: true,
	}, 1280, 800)
	require.NoError(t, err)
	defer s.Stop("test finished")

	require.True(t, sawToken.Load(), "the app should have received the bearer token")
	var title string
	require.NoError(t, chromedp.Run(s.(*session).ctx, chromedp.Title(&title)))
	require.Equal(t, "Web app test", title)

	require.Eventually(t, sawCookie.Load, 5*time.Second, 50*time.Millisecond, "injecting the header must not drop the app's cookies")
	select {
	case auth := <-sideDoorAuth:
		require.Empty(t, auth, "another port on the same host must not get the credential")
	case <-time.After(5 * time.Second):
		t.Fatal("another port on the same host should still be reachable")
	}

	err = s.Navigate(t.Context(), otherHostURL+"/next")
	require.ErrorContains(t, err, "ERR_BLOCKED_BY_CLIENT")
	require.Zero(t, otherHostHits.Load(), "nothing should reach the other host")

	blocked := false
	require.Eventually(t, func() bool {
		for {
			select {
			case event, ok := <-s.Events():
				if !ok {
					return blocked
				}
				if event.Type == browser.EventBlockedRequest && strings.HasPrefix(event.URL, otherHostURL) {
					blocked = true
				}
			default:
				return blocked
			}
		}
	}, 5*time.Second, 50*time.Millisecond, "blocked requests should be reported")
}
