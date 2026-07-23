package relay

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	EnrollMethodToken = "token"
	EnrollMethodAws   = "aws"

	INFISICAL_RELAY_ACCESS_TOKEN_KEY     = "INFISICAL_RELAY_ACCESS_TOKEN"
	INFISICAL_RELAY_DOMAIN_KEY           = "INFISICAL_RELAY_DOMAIN"
	INFISICAL_RELAY_ENROLLMENT_TOKEN_KEY = "INFISICAL_RELAY_ENROLLMENT_TOKEN"
	INFISICAL_RELAY_ID_KEY               = "INFISICAL_RELAY_ID"
	INFISICAL_RELAY_ENROLL_METHOD_KEY    = "INFISICAL_RELAY_ENROLL_METHOD"
)

func relayConfPath(name string) (string, error) {
	if os.Geteuid() == 0 {
		return filepath.Join("/etc/infisical/relays", name+".conf"), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}

	return filepath.Join(homeDir, ".infisical", "relays", name+".conf"), nil
}

func loadConfKey(name, key string) (string, error) {
	confPath, err := relayConfPath(name)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(confPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read relay config: %w", err)
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

func saveConfKey(name, key, value string) error {
	confPath, err := relayConfPath(name)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(confPath), 0700); err != nil {
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
		return fmt.Errorf("failed to write relay config: %w", err)
	}

	return nil
}

func LoadStoredAccessToken(name string) (string, error) {
	if envToken := os.Getenv(INFISICAL_RELAY_ACCESS_TOKEN_KEY); envToken != "" {
		return envToken, nil
	}
	return loadConfKey(name, INFISICAL_RELAY_ACCESS_TOKEN_KEY)
}

func SaveAccessToken(name, token string) error {
	return saveConfKey(name, INFISICAL_RELAY_ACCESS_TOKEN_KEY, token)
}

func LoadStoredDomain(name string) (string, error) {
	return loadConfKey(name, INFISICAL_RELAY_DOMAIN_KEY)
}

func SaveDomain(name, domain string) error {
	return saveConfKey(name, INFISICAL_RELAY_DOMAIN_KEY, domain)
}

func LoadStoredEnrollmentToken(name string) (string, error) {
	return loadConfKey(name, INFISICAL_RELAY_ENROLLMENT_TOKEN_KEY)
}

func SaveEnrollmentToken(name, token string) error {
	return saveConfKey(name, INFISICAL_RELAY_ENROLLMENT_TOKEN_KEY, token)
}

func LoadStoredRelayID(name string) (string, error) {
	if envID := os.Getenv(INFISICAL_RELAY_ID_KEY); envID != "" {
		return envID, nil
	}
	return loadConfKey(name, INFISICAL_RELAY_ID_KEY)
}

func SaveRelayID(name, relayID string) error {
	return saveConfKey(name, INFISICAL_RELAY_ID_KEY, relayID)
}

func GetConfPathDisplay(name string) string {
	path, err := relayConfPath(name)
	if err != nil {
		if runtime.GOOS == "linux" {
			return "/etc/infisical/relays/" + name + ".conf"
		}
		return "~/.infisical/relays/" + name + ".conf"
	}
	return path
}
