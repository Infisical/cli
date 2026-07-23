//go:build darwin

package cmd

import (
	"os/exec"
)

// ensureCATrusted makes sure the local root at certPath is a trusted anchor in the login keychain, so
// native-trust clients (Go CLIs like gh) accept the proxy's leaves. It is silent when the cert is
// already trusted; installing (first run, or after removal/expiry) triggers a one-time macOS password
// prompt. Returns (installed, error): installed=true means an anchor was just added.
//
// This only affects cert TRUST. It never touches keychain secrets: securityd stays blocked in the
// sandbox, so the agent still cannot read the login token.
func ensureCATrusted(certPath string) (bool, error) {
	if trustSettingsPresent(certPath) {
		return false, nil
	}
	// add-trusted-cert into the user (login) keychain; -r trustRoot marks it a trusted anchor.
	// #nosec G204 -- certPath is a path we control under ~/.infisical
	cmd := exec.Command("security", "add-trusted-cert", "-r", "trustRoot", certPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, &trustInstallError{out: string(out), err: err}
	}
	return true, nil
}

// trustSettingsPresent reports whether the cert already has trust settings (i.e. is a trusted anchor),
// without prompting. `security verify-cert` succeeds only if the chain is trusted.
func trustSettingsPresent(certPath string) bool {
	// #nosec G204 -- certPath is a path we control
	return exec.Command("security", "verify-cert", "-c", certPath).Run() == nil
}

type trustInstallError struct {
	out string
	err error
}

func (e *trustInstallError) Error() string {
	return "failed to trust the local CA in the keychain: " + e.err.Error() + " (" + e.out + ")"
}
