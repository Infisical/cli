//go:build darwin

package cmd

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

// The keychain prompt is a dialog on the machine's own screen. Unanswered, it used to hold av run
// forever with nothing printed, which is what CI and an SSH session both look like.
func TestKeychainTrustGivesUpInsteadOfWaitingForever(t *testing.T) {
	originalTimeout, originalCommand := agentVaultTrustTimeout, agentVaultTrustCommand
	t.Cleanup(func() { agentVaultTrustTimeout, agentVaultTrustCommand = originalTimeout, originalCommand })

	agentVaultTrustTimeout = 100 * time.Millisecond
	agentVaultTrustCommand = func(ctx context.Context, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "30")
	}

	prompted := false
	start := time.Now()
	installed, err := ensureAgentVaultCATrusted(t.TempDir()+"/absent.pem", func() { prompted = true })

	if !errors.Is(err, errAgentVaultTrustTimedOut) {
		t.Fatalf("err = %v, want the timeout", err)
	}
	if installed {
		t.Fatal("nothing was installed")
	}
	if !prompted {
		t.Fatal("the run must say what it is waiting for before it waits")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v: the deadline did not cut it short", elapsed)
	}
}
