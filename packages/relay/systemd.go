package relay

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	gatewayv2 "github.com/Infisical/infisical-merge/packages/gateway-v2"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

const relaysConfigDir = "/etc/infisical/relays"

// legacy paths used by older installs that hardcoded a single relay service
const (
	legacyRelayServiceName = "infisical-relay"
	legacyRelayConfigPath  = "/etc/infisical/relay.conf"
)

// relayServiceFilePath returns the systemd unit path for a relay with the given name.
func relayServiceFilePath(name string) string {
	return fmt.Sprintf("/etc/systemd/system/%s.service", name)
}

// relayEnvFilePath returns the systemd environment file path for a relay. Kept distinct from the
// per-relay config file (<name>.conf) so SaveAccessToken and the env file don't clobber each other.
func relayEnvFilePath(name string) string {
	return filepath.Join(relaysConfigDir, name+".env.conf")
}

// InstallRelaySystemdService installs the systemd unit and writes configuration for the relay.
// token is used for org-type relays (written as INFISICAL_TOKEN). For instance-type relays,
// relayAuthSecret is written as INFISICAL_RELAY_AUTH_SECRET.
func InstallRelaySystemdService(token string, domain string, name string, host string, instanceType string, relayAuthSecret string, serviceLogFile string) (string, error) {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return "", nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return "", nil
	}

	if err := os.MkdirAll(relaysConfigDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	// Build config content
	// Relay identity/name and network settings
	configContent := fmt.Sprintf("%s=%s\n%s=%s\n%s=%s\n",
		gatewayv2.RELAY_NAME_ENV_NAME, name,
		gatewayv2.RELAY_HOST_ENV_NAME, host,
		gatewayv2.RELAY_TYPE_ENV_NAME, instanceType)

	// API URL for self-hosted
	if domain != "" {
		configContent += fmt.Sprintf("INFISICAL_API_URL=%s\n", domain)
	}

	// Auth settings
	if instanceType == "instance" {
		if relayAuthSecret != "" {
			configContent += fmt.Sprintf("%s=%s\n", gatewayv2.RELAY_AUTH_SECRET_ENV_NAME, relayAuthSecret)
		}
	} else {
		if token != "" {
			configContent += fmt.Sprintf("INFISICAL_TOKEN=%s\n", token)
		}
	}

	environmentFilePath := relayEnvFilePath(name)
	if err := os.WriteFile(environmentFilePath, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write environment file: %v", err)
	}

	return finalizeRelaySystemdInstall(name, environmentFilePath, serviceLogFile)
}

// InstallEnrolledRelaySystemdService installs the systemd service for a relay that was
// enrolled via the enrollment token flow. It saves the long-lived relay access token
// to the per-relay config file (same location relay start uses) and writes minimal
// env vars to the systemd environment file. The systemd service is named after the relay
// so multiple relays can run on the same machine.
func InstallEnrolledRelaySystemdService(accessToken string, domain string, name string, serviceLogFile string) (string, error) {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return "", nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return "", nil
	}

	// Save the access token to the per-relay config file (same as relay start does)
	if err := SaveAccessToken(name, accessToken); err != nil {
		return "", fmt.Errorf("failed to save access token: %v", err)
	}

	// Save domain if provided
	if domain != "" {
		if err := SaveDomain(name, domain); err != nil {
			return "", fmt.Errorf("failed to save domain: %v", err)
		}
	}

	// Write minimal env vars to systemd environment file
	if err := os.MkdirAll(relaysConfigDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	configContent := fmt.Sprintf("%s=%s\n", INFISICAL_RELAY_ENROLL_METHOD_KEY, EnrollMethodToken)
	configContent += fmt.Sprintf("%s=%s\n", gatewayv2.RELAY_NAME_ENV_NAME, name)
	if domain != "" {
		configContent += fmt.Sprintf("INFISICAL_API_URL=%s\n", domain)
	}

	environmentFilePath := relayEnvFilePath(name)
	if err := os.WriteFile(environmentFilePath, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write environment file: %v", err)
	}

	return finalizeRelaySystemdInstall(name, environmentFilePath, serviceLogFile)
}

// InstallAwsAuthRelaySystemdService installs the systemd service for a relay using AWS Auth.
// Unlike the token-auth flow, no JWT is written into the env file — the relay performs a
// fresh STS-signed login on each service start using whatever AWS credentials it can resolve
// (instance role, env vars, shared profile). We just persist the relay id, domain, and name
// so `relay start` can re-authenticate. The systemd service is named after the relay so
// multiple relays can run on the same machine.
func InstallAwsAuthRelaySystemdService(relayID string, domain string, name string, serviceLogFile string) (string, error) {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return "", nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return "", nil
	}

	if err := os.MkdirAll(relaysConfigDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	configContent := fmt.Sprintf("%s=%s\n", INFISICAL_RELAY_ID_KEY, relayID)
	configContent += fmt.Sprintf("%s=%s\n", INFISICAL_RELAY_ENROLL_METHOD_KEY, EnrollMethodAws)
	if domain != "" {
		configContent += fmt.Sprintf("INFISICAL_API_URL=%s\n", domain)
	}
	configContent += fmt.Sprintf("%s=%s\n", gatewayv2.RELAY_NAME_ENV_NAME, name)

	environmentFilePath := relayEnvFilePath(name)
	if err := os.WriteFile(environmentFilePath, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write environment file: %v", err)
	}

	return finalizeRelaySystemdInstall(name, environmentFilePath, serviceLogFile)
}

// finalizeRelaySystemdInstall writes the systemd unit + logrotate files for a relay named `name`,
// reloads systemd, and returns the resolved service name.
func finalizeRelaySystemdInstall(name string, environmentFilePath string, serviceLogFile string) (string, error) {
	serviceName := name

	if err := util.WriteSystemdServiceFile(serviceLogFile, environmentFilePath, serviceName, "relay", fmt.Sprintf("Infisical Relay Service (%s)", name)); err != nil {
		return "", fmt.Errorf("failed to write systemd service file: %v", err)
	}

	if err := util.WriteLogrotateFile(serviceLogFile, serviceName); err != nil {
		return "", fmt.Errorf("failed to write logrotate file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msgf("Successfully installed systemd service '%s'", serviceName)
	log.Info().Msgf("To start the service, run: sudo systemctl start %s", serviceName)
	log.Info().Msgf("To enable the service on boot, run: sudo systemctl enable %s", serviceName)

	return serviceName, nil
}

func UninstallRelaySystemdService(name string) error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service uninstallation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service uninstallation - not running as root/sudo")
		return nil
	}

	// Resolve service name + paths. An empty name targets the legacy hardcoded service
	// for backwards compatibility with older installs.
	serviceName := name
	envFilePath := relayEnvFilePath(name)
	perRelayConfPath := filepath.Join(relaysConfigDir, name+".conf")
	if name == "" {
		serviceName = legacyRelayServiceName
		envFilePath = legacyRelayConfigPath
		perRelayConfPath = ""
	}

	servicePath := relayServiceFilePath(serviceName)
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		if name == "" {
			return fmt.Errorf("no relay service found")
		}
		return fmt.Errorf("no relay service found for '%s'", name)
	}

	// Stop the service if it's running
	stopCmd := exec.Command("systemctl", "stop", serviceName)
	if err := stopCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to stop service: %v", err)
	}

	// Disable the service
	disableCmd := exec.Command("systemctl", "disable", serviceName)
	if err := disableCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to disable service: %v", err)
	}

	// Remove the service file
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd service file: %v", err)
	}

	// Remove the systemd environment file
	if err := os.Remove(envFilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove environment file: %v", err)
	}

	// Remove the per-relay config file (holds the stored access token/domain for enrolled/aws flows)
	if perRelayConfPath != "" {
		if err := os.Remove(perRelayConfPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove config file: %v", err)
		}
	}

	// Remove the logrotate file if install created one
	if err := os.Remove(filepath.Join("/etc/logrotate.d", serviceName)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove logrotate file: %v", err)
	}

	// Reload systemd to apply changes
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msgf("Successfully uninstalled Infisical Relay systemd service '%s'", serviceName)
	return nil
}
