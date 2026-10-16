package browser

import (
	"os"
	"os/exec"
)

const (
	BinaryEnvName     = "INFISICAL_BROWSER_BINARY"
	DefaultBinaryPath = "/usr/bin/chromium-headless-shell"
)

// Returns "" when the binary is missing or not executable.
func BinaryPath() string {
	path := os.Getenv(BinaryEnvName)
	if path == "" {
		path = DefaultBinaryPath
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return ""
	}
	return resolved
}

// A runtime check rather than a build tag: one binary serves both the plain and browser images.
func IsSupported() bool {
	return BinaryPath() != ""
}
