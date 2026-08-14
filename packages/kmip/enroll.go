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

// Deliberately conf-file only, unlike the loaders above. The env var is how an operator asks for a
// method on this run; the conf file records how the server actually enrolled, which is what tells
// us whether it can re-authenticate on its own.
func LoadStoredEnrollMethod(name string) (string, error) {
	return loadConfKey(name, INFISICAL_KMIP_ENROLL_METHOD_KEY)
}

func SaveEnrollMethod(name, method string) error {
	return saveConfKey(name, INFISICAL_KMIP_ENROLL_METHOD_KEY, method)
}

// Conf-file only, for deciding what a server is rather than what this run asked for. Servers
// enrolled before the method was recorded have a server ID here and nothing else, which is what
// identifies them as AWS-enrolled.
func LoadPersistedServerID(name string) (string, error) {
	return loadConfKey(name, INFISICAL_KMIP_SERVER_ID_KEY)
}

// Reports the server ID to re-authenticate with when a stored access token is rejected mid-run,
// and whether STS refresh applies at all. Both reads ignore the environment: INFISICAL_KMIP_SERVER_ID
// says what this run was handed, not how the server enrolled, so honouring it here would wire a
// token-enrolled server for a refresh it cannot perform and turn a rejected token into an AWS error.
// A server enrolled before the method was recorded is identified by a conf-file server ID alone.
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
