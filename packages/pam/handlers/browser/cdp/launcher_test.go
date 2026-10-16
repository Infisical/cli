package cdp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/browser"
	"github.com/stretchr/testify/require"
)

func TestExecLauncherStartsAndStopsBrowser(t *testing.T) {
	binary := browser.BinaryPath()
	if binary == "" {
		t.Skipf("no browser binary found; set %s to run this test", browser.BinaryEnvName)
	}
	profileRoot := t.TempDir()
	launcher := NewExecLauncher(ExecLauncherConfig{
		BinaryPath:  binary,
		ProfileRoot: profileRoot,
		// Chromium won't run as root with its sandbox on.
		NoSandbox: os.Geteuid() == 0,
	})

	instance, err := launcher.Launch(t.Context(), LaunchOptions{})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(instance.CDPURL, "ws://127.0.0.1:"), instance.CDPURL)

	endpoint, err := url.Parse(instance.CDPURL)
	require.NoError(t, err)
	resp, err := http.Get("http://" + endpoint.Host + "/json/version")
	require.NoError(t, err)
	var version struct {
		Browser string `json:"Browser"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&version))
	resp.Body.Close()
	require.NotEmpty(t, version.Browser)

	profiles, err := os.ReadDir(profileRoot)
	require.NoError(t, err)
	require.Len(t, profiles, 1)

	instance.Stop()

	select {
	case <-instance.Done():
	default:
		t.Fatal("browser still running after Stop")
	}
	profiles, err = os.ReadDir(profileRoot)
	require.NoError(t, err)
	require.Empty(t, profiles)
}

func TestExecLauncherDisablesZygoteOnlyWithoutSandbox(t *testing.T) {
	sandboxed := NewExecLauncher(ExecLauncherConfig{BinaryPath: "/usr/bin/chromium-headless-shell"}).args("/profile", LaunchOptions{})
	require.NotContains(t, sandboxed, "--no-sandbox")
	require.NotContains(t, sandboxed, "--no-zygote")
	require.NotContains(t, sandboxed, "--headless=new")

	unsandboxed := NewExecLauncher(ExecLauncherConfig{BinaryPath: "/usr/bin/chromium", NoSandbox: true}).args("/profile", LaunchOptions{})
	require.Contains(t, unsandboxed, "--no-sandbox")
	require.Contains(t, unsandboxed, "--no-zygote")
	require.Contains(t, unsandboxed, "--headless=new")
}
