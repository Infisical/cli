package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAgentServiceName(t *testing.T) {
	for _, name := range []string{"infisical-agent", "chef.secrets_1", "A"} {
		assert.NoError(t, validateAgentServiceName(name), "name %q", name)
	}

	for _, name := range []string{"", "-agent", "my agent", "agent@1", "../agent", `agent\x`, strings.Repeat("a", 129), "NUL", "con", "COM1", "lpt9.agent"} {
		assert.Error(t, validateAgentServiceName(name), "name %q", name)
	}
}
