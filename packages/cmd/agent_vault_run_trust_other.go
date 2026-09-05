//go:build !darwin

package cmd

import "errors"

var errAgentVaultTrustTimedOut = errors.New("the keychain prompt went unanswered")

// Only macOS needs a keychain-trusted anchor; elsewhere the CA environment variables are enough.
func ensureAgentVaultCATrusted(string, func()) (bool, error) { return false, nil }
