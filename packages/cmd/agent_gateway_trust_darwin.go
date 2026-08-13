//go:build darwin

package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ensureCATrusted makes a CA a trusted anchor in the login keychain, so tools that use the OS trust store
// (gh, and most Go programs) accept the broker's leaves. Silent if already trusted; installing triggers a
// one-time password prompt. Affects certificate trust only: securityd stays blocked, so keychain secrets
// remain unreadable.
func ensureCATrusted(certPath string) (bool, error) {
	commonName, err := certificateCommonName(certPath)
	if err != nil {
		return false, err
	}

	if isTrustedAnchor(commonName) {
		return false, nil
	}

	// -k is passed explicitly: without it the destination keychain is ambiguous and the add can succeed while
	// storing nothing, which is how this failed silently before.
	home, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}
	loginKeychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")

	// #nosec G204 -- certPath is a path we control under ~/.infisical
	cmd := exec.Command("security", "add-trusted-cert", "-r", "trustRoot", "-k", loginKeychain, certPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, &trustInstallError{out: string(out), err: err, certPath: certPath}
	}

	// Verified rather than assumed: add-trusted-cert can exit 0 having stored nothing, and reporting success
	// when a later request will fail its TLS handshake is worse than reporting nothing at all.
	if !isTrustedAnchor(commonName) {
		return false, &trustInstallError{
			out:      "the certificate was not recorded as a trusted anchor afterwards",
			err:      fmt.Errorf("trust settings did not persist"),
			certPath: certPath,
		}
	}

	return true, nil
}

// isTrustedAnchor asks for the trust settings themselves, in the user and admin domains. `verify-cert` is
// not usable for this: it reports success for a self-signed CA that nothing trusts, which made the previous
// check always answer "already trusted".
func isTrustedAnchor(commonName string) bool {
	if commonName == "" {
		return false
	}

	for _, args := range [][]string{{"dump-trust-settings"}, {"dump-trust-settings", "-d"}} {
		out, err := exec.Command("security", args...).CombinedOutput()
		if err != nil {
			// No trust settings in that domain at all, which is a legitimate answer rather than a failure.
			continue
		}
		if strings.Contains(string(out), commonName) {
			return true
		}
	}
	return false
}

func certificateCommonName(certPath string) (string, error) {
	raw, err := os.ReadFile(certPath) // #nosec G304 -- a path we control under ~/.infisical
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return "", fmt.Errorf("%s is not a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return cert.Subject.CommonName, nil
}

type trustInstallError struct {
	out      string
	err      error
	certPath string
}

// The message carries the manual command, because the usual cause is a policy that stops a user-domain
// install, and the System keychain needs a privilege the CLI should not take for itself.
func (e *trustInstallError) Error() string {
	return fmt.Sprintf(
		"%v (%s). Trust it manually with: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
		e.err,
		strings.TrimSpace(e.out),
		e.certPath,
	)
}
