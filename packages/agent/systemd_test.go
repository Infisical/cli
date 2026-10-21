//go:build !windows

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckPathsVisibleToSystemd(t *testing.T) {
	assert.NoError(t, CheckPathsVisibleToSystemd([]string{"/etc/infisical/agents/app.yaml", "/var/log/infisical/app.log", "/opt/app/.env", "/homework/app", "/tmpfiles/app", "/var/tmpfiles/app"}))

	for _, path := range []string{"/home/ubuntu/agent.yaml", "/home", "/tmp/access-token", "/var/tmp/app/.env", "/etc/../home/app"} {
		assert.Error(t, CheckPathsVisibleToSystemd([]string{"/etc/infisical/agents/app.yaml", path}), "path %q", path)
	}
}
