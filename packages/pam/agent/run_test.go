package agent

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
)

// This list is maintained by hand while the agent proxy derives its own from the shared one, so
// adding an auth method to the CLI would update that one and silently leave this behind.
func TestInfisicalAuthEnvKeysCoverMachineIdentityAuthEnvVars(t *testing.T) {
	stripped := make(map[string]bool, len(infisicalAuthEnvKeys))
	for _, key := range infisicalAuthEnvKeys {
		stripped[key] = true
	}

	for _, key := range util.MachineIdentityAuthEnvVars {
		if !stripped[key] {
			t.Errorf("%s reaches the agent; add it to infisicalAuthEnvKeys", key)
		}
	}
}
