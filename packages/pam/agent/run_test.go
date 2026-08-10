package agent

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
)

// infisicalAuthEnvKeys is maintained here by hand, while the agent proxy derives its own scrub list
// from util.MachineIdentityAuthEnvVars. That is fine as long as this list stays a superset: an agent
// launched by `pam agentic access` must not inherit a variable the CLI's auth resolution reads, or it
// could authenticate to the API directly and open sessions outside the accounts, duration and approval
// gates the run was launched with.
//
// Without this test the two lists drift silently. Adding an auth method to the CLI updates the shared
// list, the agent proxy picks it up automatically, and PAM would not.
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
