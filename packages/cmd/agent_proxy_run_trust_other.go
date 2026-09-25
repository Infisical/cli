//go:build !darwin

package cmd

// ensureCATrusted is a no-op off macOS: only macOS needs a keychain-trusted anchor for native-trust
// clients. Elsewhere (Linux) the injected CA env var is enough.
func ensureCATrusted(string) (bool, error) { return false, nil }
