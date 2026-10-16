package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Infisical/infisical-merge/packages/config"
)

func writeAgentServiceTestConfig(t *testing.T, path string, exitAfterAuth bool) {
	t.Helper()

	// ParseAgentConfig points the CLI at the config's address; put it back for the other tests
	previousURL := config.INFISICAL_URL
	t.Cleanup(func() { config.INFISICAL_URL = previousURL })

	content := fmt.Sprintf(`infisical:
  address: "http://127.0.0.1:1"
  exit-after-auth: %t
auth:
  type: "universal-auth"
  config:
    client-id: "./client-id"
    client-secret: "./client-secret"
`, exitAfterAuth)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestNewAgentServiceOptions(t *testing.T) {
	dir := t.TempDir()
	writeAgentServiceTestConfig(t, filepath.Join(dir, "agent-config.yaml"), false)
	t.Chdir(dir)

	opts, err := newAgentServiceOptions("infisical-agent", "agent-config.yaml")
	require.NoError(t, err)

	// a relative config path is stored as an absolute one
	require.True(t, filepath.IsAbs(opts.ConfigPath), opts.ConfigPath)
	configInfo, err := os.Stat(opts.ConfigPath)
	require.NoError(t, err)
	expectedInfo, err := os.Stat(filepath.Join(dir, "agent-config.yaml"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(expectedInfo, configInfo))

	// the service runs a copy of exactly the config that was checked
	content, err := os.ReadFile(opts.ConfigPath)
	require.NoError(t, err)
	assert.Equal(t, content, opts.ConfigData)

	assert.True(t, filepath.IsAbs(opts.Executable), opts.Executable)
	assert.Equal(t, "infisical-agent", opts.Name)
}

func TestNewAgentServiceOptionsRejectsBadInput(t *testing.T) {
	dir := t.TempDir()

	exitAfterAuthConfig := filepath.Join(dir, "exit-after-auth.yaml")
	writeAgentServiceTestConfig(t, exitAfterAuthConfig, true)
	_, err := newAgentServiceOptions("infisical-agent", exitAfterAuthConfig)
	assert.ErrorContains(t, err, "exit-after-auth")

	_, err = newAgentServiceOptions("infisical-agent", filepath.Join(dir, "missing.yaml"))
	assert.ErrorContains(t, err, "unable to read the agent config")

	unsupportedAuthConfig := filepath.Join(dir, "unsupported-auth.yaml")
	require.NoError(t, os.WriteFile(unsupportedAuthConfig, []byte("auth:\n  type: \"not-a-method\"\n"), 0o600))
	_, err = newAgentServiceOptions("infisical-agent", unsupportedAuthConfig)
	assert.ErrorContains(t, err, "not-a-method")

	validConfig := filepath.Join(dir, "agent-config.yaml")
	writeAgentServiceTestConfig(t, validConfig, false)
	_, err = newAgentServiceOptions("bad name", validConfig)
	assert.ErrorContains(t, err, "invalid service name")
}

func TestAgentServiceLogFile(t *testing.T) {
	t.Setenv("ProgramData", `D:\Data`)
	assert.Equal(t, `D:\Data\Infisical\Agent\chef-secrets.log`, agentServiceLogFile("chef-secrets"))
}

func TestAgentServiceLogFolderRefusesLinks(t *testing.T) {
	// standard users can create junctions, so one in place of the log folder could redirect the agent's logs
	target := t.TempDir()
	junction := filepath.Join(t.TempDir(), "Agent")
	require.NoError(t, exec.Command("cmd", "/c", "mklink", "/J", junction, target).Run())

	assert.ErrorContains(t, checkOwnedByAdministrators(junction), "is a link to another location")
	assert.ErrorContains(t, checkOwnedByAdministrators(filepath.Join(target, "missing.log")), "unable to open")
}
