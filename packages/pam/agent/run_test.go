package agent

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
)

// Maintained by hand, while the agent proxy derives its own from the shared list.
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
