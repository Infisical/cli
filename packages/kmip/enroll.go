package kmip

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

	INFISICAL_KMIP_ACCESS_TOKEN_KEY     = "INFISICAL_KMIP_ACCESS_TOKEN"
	INFISICAL_KMIP_DOMAIN_KEY           = "INFISICAL_KMIP_DOMAIN"
	INFISICAL_KMIP_ENROLLMENT_TOKEN_KEY = "INFISICAL_KMIP_ENROLLMENT_TOKEN"
	INFISICAL_KMIP_SERVER_ID_KEY        = "INFISICAL_KMIP_SERVER_ID"
	INFISICAL_KMIP_ENROLL_METHOD_KEY    = "INFISICAL_KMIP_ENROLL_METHOD"
)

func kmipConfPath(name string) (string, error) {
	if os.Geteuid() == 0 {
		return filepath.Join("/etc/infisical/kmip", name+".conf"), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}

	return filepath.Join(homeDir, ".infisical", "kmip", name+".conf"), nil
}

func loadConfKey(name, key string) (string, error) {
	confPath, err := kmipConfPath(name)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(confPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read kmip config: %w", err)
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
	confPath, err := kmipConfPath(name)
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
		return fmt.Errorf("failed to write kmip config: %w", err)
	}

	return nil
}

func LoadStoredAccessToken(name string) (string, error) {
	if envToken := os.Getenv(INFISICAL_KMIP_ACCESS_TOKEN_KEY); envToken != "" {
		return envToken, nil
	}
	return loadConfKey(name, INFISICAL_KMIP_ACCESS_TOKEN_KEY)
}

func SaveAccessToken(name, token string) error {
	return saveConfKey(name, INFISICAL_KMIP_ACCESS_TOKEN_KEY, token)
}

func LoadStoredDomain(name string) (string, error) {
	return loadConfKey(name, INFISICAL_KMIP_DOMAIN_KEY)
}

func SaveDomain(name, domain string) error {
	return saveConfKey(name, INFISICAL_KMIP_DOMAIN_KEY, domain)
}

func LoadStoredEnrollmentToken(name string) (string, error) {
	return loadConfKey(name, INFISICAL_KMIP_ENROLLMENT_TOKEN_KEY)
}

func SaveEnrollmentToken(name, token string) error {
	return saveConfKey(name, INFISICAL_KMIP_ENROLLMENT_TOKEN_KEY, token)
}

func LoadStoredServerID(name string) (string, error) {
	if envID := os.Getenv(INFISICAL_KMIP_SERVER_ID_KEY); envID != "" {
		return envID, nil
	}
	return loadConfKey(name, INFISICAL_KMIP_SERVER_ID_KEY)
}

func SaveServerID(name, kmipServerID string) error {
	return saveConfKey(name, INFISICAL_KMIP_SERVER_ID_KEY, kmipServerID)
}

// Conf-file only: the env var says what this run asked for, not how the server enrolled.
func LoadStoredEnrollMethod(name string) (string, error) {
	return loadConfKey(name, INFISICAL_KMIP_ENROLL_METHOD_KEY)
}

func SaveEnrollMethod(name, method string) error {
	return saveConfKey(name, INFISICAL_KMIP_ENROLL_METHOD_KEY, method)
}

func LoadPersistedServerID(name string) (string, error) {
	return loadConfKey(name, INFISICAL_KMIP_SERVER_ID_KEY)
}

// Ignores the environment throughout: honouring INFISICAL_KMIP_SERVER_ID here would wire a
// token-enrolled server for an STS refresh it cannot perform. A missing method means the server
// enrolled before it was recorded, where a conf-file server ID identifies AWS enrollment.
func ResolveAwsRefreshServerID(name string) (string, bool) {
	method, _ := LoadStoredEnrollMethod(name)
	serverID, _ := LoadPersistedServerID(name)
	if serverID == "" {
		return "", false
	}
	return serverID, method == EnrollMethodAws || method == ""
}

func GetConfPathDisplay(name string) string {
	path, err := kmipConfPath(name)
	if err != nil {
		if runtime.GOOS == "linux" {
			return "/etc/infisical/kmip/" + name + ".conf"
		}
		return "~/.infisical/kmip/" + name + ".conf"
	}
	return path
}
