//go:build darwin

package cmd

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

// Adding the anchor puts a macOS dialog on screen. With nobody to answer it the command waits forever,
// and av run has printed nothing by then, so the first command a new user runs looks hung rather than
// blocked on a question.
var agentVaultTrustTimeout = 30 * time.Second

// Swapped in tests: the real command puts a dialog on screen and would sit there.
var agentVaultTrustCommand = func(ctx context.Context, certPath string) *exec.Cmd {
	// #nosec G204 -- certPath is a path we control under ~/.infisical
	return exec.CommandContext(ctx, "security", "add-trusted-cert", "-r", "trustRoot", certPath)
}

var errAgentVaultTrustTimedOut = errors.New("the keychain prompt went unanswered")

// ensureAgentVaultCATrusted is ensureCATrusted bounded by a deadline, and it says when it is about to
// ask. onPrompt runs only when the anchor is actually missing, so a proxy already trusted stays silent.
func ensureAgentVaultCATrusted(certPath string, onPrompt func()) (bool, error) {
	if trustSettingsPresent(certPath) {
		return false, nil
	}
	onPrompt()

	ctx, cancel := context.WithTimeout(context.Background(), agentVaultTrustTimeout)
	defer cancel()

	out, err := agentVaultTrustCommand(ctx, certPath).CombinedOutput()
	if ctx.Err() != nil {
		return false, errAgentVaultTrustTimedOut
	}
	if err != nil {
		return false, &trustInstallError{out: string(out), err: err}
	}
	return true, nil
}
