//go:build darwin

package cmd

import (
	"os/exec"
)

// ensureCATrusted makes the local root a trusted anchor in the login keychain, so Go tools like gh
// accept the proxy's leaves. Silent if already trusted; installing triggers a one-time password
// prompt. Affects cert trust only: securityd stays blocked, so keychain secrets remain unreadable.
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
