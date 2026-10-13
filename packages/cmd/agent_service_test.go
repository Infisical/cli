package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestRenderAgentSystemdUnit(t *testing.T) {
	unit, err := renderAgentSystemdUnit(agentServiceOptions{
		Name:       "infisical-agent",
		Executable: "/usr/local/bin/infisical",
		ConfigPath: "/etc/infisical/agent-config.yaml",
	})
	require.NoError(t, err)

	assert.Contains(t, unit, agentServiceMarker)
	assert.Contains(t, unit, "\nDescription=Infisical Agent (infisical-agent)\n")
	assert.Contains(t, unit, "\nType=notify\n")
	assert.Contains(t, unit, "\nExecStart=/usr/local/bin/infisical agent --config /etc/infisical/agent-config.yaml\n")
	assert.Contains(t, unit, "\nWorkingDirectory=/etc/infisical\n")
	assert.Contains(t, unit, "\nRestart=on-failure\n")
	assert.NotContains(t, unit, "--log-file")
}

func TestRenderAgentSystemdUnitEscapesPaths(t *testing.T) {
	unit, err := renderAgentSystemdUnit(agentServiceOptions{
		Name:       "chef-secrets",
		Executable: "/opt/infisical/infisical",
		ConfigPath: "/srv/my configs/100%/agent.yaml",
		LogFile:    "/var/log/infisical/$agent.log",
	})
	require.NoError(t, err)

	assert.Contains(t, unit, "\nExecStart=/opt/infisical/infisical agent --config \"/srv/my configs/100%%/agent.yaml\" --log-file /var/log/infisical/$$agent.log\n")
	assert.Contains(t, unit, "\nWorkingDirectory=/srv/my configs/100%%\n")
}

func TestSystemdQuoteArg(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/infisical": "/usr/bin/infisical",
		"":                   `""`,
		"with space":         `"with space"`,
		`with "quotes"`:      `"with \"quotes\""`,
		`back\slash`:         `"back\\slash"`,
		";":                  `";"`,
		"50%":                "50%%",
		"$HOME":              "$$HOME",
	}

	for arg, expected := range cases {
		assert.Equal(t, expected, systemdQuoteArg(arg), "arg %q", arg)
	}
}

func TestValidateAgentServiceName(t *testing.T) {
	for _, name := range []string{"infisical-agent", "chef.secrets_1", "A"} {
		assert.NoError(t, validateAgentServiceName(name), "name %q", name)
	}

	for _, name := range []string{"", "-agent", "my agent", "agent@1", "../agent", `agent\x`, strings.Repeat("a", 129)} {
		assert.Error(t, validateAgentServiceName(name), "name %q", name)
	}
}

func TestNewAgentServiceOptions(t *testing.T) {
	dir := t.TempDir()
	writeAgentServiceTestConfig(t, filepath.Join(dir, "agent-config.yaml"), false)
	t.Chdir(dir)

	opts, err := newAgentServiceOptions("infisical-agent", "agent-config.yaml", "")
	require.NoError(t, err)

	// a relative config path is stored as an absolute one
	require.True(t, filepath.IsAbs(opts.ConfigPath), opts.ConfigPath)
	configInfo, err := os.Stat(opts.ConfigPath)
	require.NoError(t, err)
	expectedInfo, err := os.Stat(filepath.Join(dir, "agent-config.yaml"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(expectedInfo, configInfo))

	assert.True(t, filepath.IsAbs(opts.Executable), opts.Executable)
	assert.Equal(t, defaultAgentServiceLogFile("infisical-agent"), opts.LogFile)

	expectedArgs := []string{"agent", "--config", opts.ConfigPath}
	if opts.LogFile != "" {
		expectedArgs = append(expectedArgs, "--log-file", opts.LogFile)
	}
	assert.Equal(t, expectedArgs, opts.args())
}

func TestNewAgentServiceOptionsWithLogFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent-config.yaml")
	writeAgentServiceTestConfig(t, configPath, false)
	logFile := filepath.Join(dir, "logs", "agent.log")

	opts, err := newAgentServiceOptions("chef-secrets", configPath, logFile)
	require.NoError(t, err)

	assert.Equal(t, logFile, opts.LogFile)
	assert.Equal(t, []string{"agent", "--config", configPath, "--log-file", logFile}, opts.args())
}

func TestNewAgentServiceOptionsRejectsBadInput(t *testing.T) {
	dir := t.TempDir()

	exitAfterAuthConfig := filepath.Join(dir, "exit-after-auth.yaml")
	writeAgentServiceTestConfig(t, exitAfterAuthConfig, true)
	_, err := newAgentServiceOptions("infisical-agent", exitAfterAuthConfig, "")
	assert.ErrorContains(t, err, "exit-after-auth")

	_, err = newAgentServiceOptions("infisical-agent", filepath.Join(dir, "missing.yaml"), "")
	assert.ErrorContains(t, err, "unable to read the agent config")

	unsupportedAuthConfig := filepath.Join(dir, "unsupported-auth.yaml")
	require.NoError(t, os.WriteFile(unsupportedAuthConfig, []byte("auth:\n  type: \"not-a-method\"\n"), 0o600))
	_, err = newAgentServiceOptions("infisical-agent", unsupportedAuthConfig, "")
	assert.ErrorContains(t, err, "not-a-method")

	validConfig := filepath.Join(dir, "agent-config.yaml")
	writeAgentServiceTestConfig(t, validConfig, false)
	_, err = newAgentServiceOptions("bad name", validConfig, "")
	assert.ErrorContains(t, err, "invalid service name")
}
