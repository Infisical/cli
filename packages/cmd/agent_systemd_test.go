//go:build !windows

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Infisical/infisical-merge/packages/config"
)

func TestAgentSystemdPathsResolveFromTheConfigDirectory(t *testing.T) {
	// ParseAgentConfig points the CLI at the config's address; put it back for the other tests
	previousURL := config.INFISICAL_URL
	t.Cleanup(func() { config.INFISICAL_URL = previousURL })

	agentConfig, err := ParseAgentConfig([]byte(`
auth:
  type: "universal-auth"
  config:
    client-id: "./client-id"
    client-secret: "/home/app/client-secret"
    remove_client_secret_on_read: false
cache:
  persistent:
    type: "file"
    path: "cache"
sinks:
  - type: "file"
    config:
      path: "access-token"
templates:
  - source-path: "templates/app.tmpl"
    destination-path: "/opt/app/.env"
`))
	require.NoError(t, err)

	paths := agentSystemdPaths("/etc/infisical/agents/app.yaml", agentConfig)

	assert.ElementsMatch(t, []string{
		"/etc/infisical/agents/app.yaml",
		"/etc/infisical/agents/client-id",
		"/home/app/client-secret",
		"/etc/infisical/agents/cache",
		"/etc/infisical/agents/templates/app.tmpl",
		"/opt/app/.env",
		"/etc/infisical/agents/access-token",
	}, paths)
}
