package gatewayv2

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	INFISICAL_GATEWAY_ACCESS_TOKEN_KEY = "INFISICAL_GATEWAY_ACCESS_TOKEN"
	INFISICAL_GATEWAY_DOMAIN_KEY       = "INFISICAL_GATEWAY_DOMAIN"
)

// gatewayConfPath returns the path to the gateway config file.
// Uses /etc/infisical/gateway.conf when running as root, otherwise ~/.infisical/gateway.conf.
func gatewayConfPath() (string, error) {
	if os.Geteuid() == 0 {
		return "/etc/infisical/gateway.conf", nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}

	return filepath.Join(homeDir, ".infisical", "gateway.conf"), nil
}

// loadConfKey reads a key from the config file. Returns empty string if not found.
func loadConfKey(key string) (string, error) {
	confPath, err := gatewayConfPath()
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(confPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read gateway config: %w", err)
	}

	prefix := key + "="
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix), nil
		}
	}

	return "", nil
}

// saveConfKey writes a key=value pair to the config file, preserving other keys.
// The file is created with 0600 permissions (owner read/write only).
func saveConfKey(key, value string) error {
	confPath, err := gatewayConfPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(confPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	var existingLines []string
	data, err := os.ReadFile(confPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read existing config: %w", err)
	}
	if err == nil {
		prefix := key + "="
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, prefix) {
				continue
			}
			existingLines = append(existingLines, line)
		}
	}

	existingLines = append(existingLines, fmt.Sprintf("%s=%s", key, value))
	content := strings.Join(existingLines, "\n") + "\n"

	if err := os.WriteFile(confPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write gateway config: %w", err)
	}

	return nil
}

// LoadStoredAccessToken reads the gateway access token from the environment or config file.
// Env var takes precedence over the config file.
// Returns an empty string if neither source has the token set.
func LoadStoredAccessToken() (string, error) {
	if envToken := os.Getenv(INFISICAL_GATEWAY_ACCESS_TOKEN_KEY); envToken != "" {
		return envToken, nil
	}
	return loadConfKey(INFISICAL_GATEWAY_ACCESS_TOKEN_KEY)
}

// SaveAccessToken writes the gateway access token to the config file.
func SaveAccessToken(token string) error {
	return saveConfKey(INFISICAL_GATEWAY_ACCESS_TOKEN_KEY, token)
}

// LoadStoredDomain reads the Infisical domain from the gateway config file.
// Returns empty string if not set (caller should use the default).
func LoadStoredDomain() (string, error) {
	return loadConfKey(INFISICAL_GATEWAY_DOMAIN_KEY)
}

// SaveDomain writes the Infisical domain to the config file.
func SaveDomain(domain string) error {
	return saveConfKey(INFISICAL_GATEWAY_DOMAIN_KEY, domain)
}

// GetConfPathDisplay returns the config path for display in log messages,
// without returning an error (falls back to a sensible default).
func GetConfPathDisplay() string {
	path, err := gatewayConfPath()
	if err != nil {
		if runtime.GOOS == "linux" {
			return "/etc/infisical/gateway.conf"
		}
		return "~/.infisical/gateway.conf"
	}
	return path
}
