//go:build !windows

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAgentSystemdPathsResolveFromTheConfigDirectory(t *testing.T) {
	agentConfig := &Config{
		Templates: []Template{{SourcePath: "templates/app.tmpl", DestinationPath: "/opt/app/.env"}},
		Sinks:     []Sink{{Type: "file", Config: SinkDetails{Path: "access-token"}}},
	}

	paths := agentSystemdPaths("/etc/infisical/agents/app.yaml", "/var/log/infisical/app.log", agentConfig)

	assert.Equal(t, []string{
		"/etc/infisical/agents/app.yaml",
		"/var/log/infisical/app.log",
		"/etc/infisical/agents/templates/app.tmpl",
		"/opt/app/.env",
		"/etc/infisical/agents/access-token",
	}, paths)
}
