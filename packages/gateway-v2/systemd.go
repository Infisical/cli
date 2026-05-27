package gatewayv2

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

const (
	legacyServiceName  = "infisical-gateway"
	legacyConfigPath   = "/etc/infisical/gateway.conf"
	legacyServicePath  = "/etc/systemd/system/infisical-gateway.service"
	gatewaysConfigDir  = "/etc/infisical/gateways"
)

func serviceName(name string) string {
	return name
}

func serviceFilePath(name string) string {
	return fmt.Sprintf("/etc/systemd/system/%s.service", serviceName(name))
}

func gatewayConfigPath(name string) string {
	return filepath.Join(gatewaysConfigDir, name+".conf")
}

type legacyInfo struct {
	exists      bool
	gatewayName string
}

func detectLegacyService() legacyInfo {
	if _, err := os.Stat(legacyServicePath); os.IsNotExist(err) {
		return legacyInfo{}
	}

	name, _ := readKeyFromConfFile(legacyConfigPath, GATEWAY_NAME_ENV_NAME)
	return legacyInfo{exists: true, gatewayName: name}
}

func logLegacyWarning(svcName string) {
	log.Warn().Msgf("Using legacy service name '%s'. To migrate to the new naming format, run: sudo infisical gateway systemd uninstall %s && sudo infisical gateway systemd install %s <original-flags>", legacyServiceName, svcName, svcName)
}

type installResult struct {
	serviceName string
	configPath  string
	isLegacy    bool
}

func resolveInstallPaths(name string) installResult {
	legacy := detectLegacyService()

	if legacy.exists && legacy.gatewayName == name {
		return installResult{
			serviceName: legacyServiceName,
			configPath:  legacyConfigPath,
			isLegacy:    true,
		}
	}

	if legacy.exists {
		log.Warn().Msgf("A legacy gateway service '%s' was found for gateway '%s'. The new gateway '%s' will be installed alongside it.", legacyServiceName, legacy.gatewayName, name)
	}

	return installResult{
		serviceName: serviceName(name),
		configPath:  gatewayConfigPath(name),
		isLegacy:    false,
	}
}

func InstallGatewaySystemdService(token string, domain string, name string, relayName string, serviceLogFile string) (string, error) {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return "", nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return "", nil
	}

	paths := resolveInstallPaths(name)

	if err := os.MkdirAll(filepath.Dir(paths.configPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	configContent := fmt.Sprintf("INFISICAL_TOKEN=%s\n", token)
	if domain != "" {
		configContent += fmt.Sprintf("INFISICAL_API_URL=%s\n", domain)
	}

	if name != "" {
		configContent += fmt.Sprintf("%s=%s\n", GATEWAY_NAME_ENV_NAME, name)
	}
	if relayName != "" {
		configContent += fmt.Sprintf("%s=%s\n", RELAY_NAME_ENV_NAME, relayName)
	}

	if err := os.WriteFile(paths.configPath, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write environment file: %v", err)
	}

	if err := util.WriteSystemdServiceFile(serviceLogFile, paths.configPath, paths.serviceName, "gateway", fmt.Sprintf("Infisical Gateway Service (%s)", name)); err != nil {
		return "", fmt.Errorf("failed to write systemd service file: %v", err)
	}

	if err := util.WriteLogrotateFile(serviceLogFile, paths.serviceName); err != nil {
		return "", fmt.Errorf("failed to write logrotate file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to reload systemd: %v", err)
	}

	if paths.isLegacy {
		logLegacyWarning(name)
	}

	log.Info().Msgf("Successfully installed systemd service '%s'", paths.serviceName)
	log.Info().Msgf("To start the service, run: sudo systemctl start %s", paths.serviceName)
	log.Info().Msgf("To enable the service on boot, run: sudo systemctl enable %s", paths.serviceName)

	return paths.serviceName, nil
}

// InstallEnrolledGatewaySystemdService installs the systemd service for a gateway that was
// enrolled via the enrollment token flow. It writes the long-lived gateway access token
// (not a machine identity token) into the environment file.
func InstallEnrolledGatewaySystemdService(accessToken string, domain string, name string, relayName string, serviceLogFile string) (string, error) {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return "", nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return "", nil
	}

	paths := resolveInstallPaths(name)

	if err := os.MkdirAll(filepath.Dir(paths.configPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	configContent := fmt.Sprintf("%s=%s\n", INFISICAL_GATEWAY_ACCESS_TOKEN_KEY, accessToken)
	if domain != "" {
		configContent += fmt.Sprintf("INFISICAL_API_URL=%s\n", domain)
	}
	if name != "" {
		configContent += fmt.Sprintf("%s=%s\n", GATEWAY_NAME_ENV_NAME, name)
	}
	if relayName != "" {
		configContent += fmt.Sprintf("%s=%s\n", RELAY_NAME_ENV_NAME, relayName)
	}

	if err := os.WriteFile(paths.configPath, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write environment file: %v", err)
	}

	if err := util.WriteSystemdServiceFile(serviceLogFile, paths.configPath, paths.serviceName, "gateway", fmt.Sprintf("Infisical Gateway Service (%s)", name)); err != nil {
		return "", fmt.Errorf("failed to write systemd service file: %v", err)
	}

	if err := util.WriteLogrotateFile(serviceLogFile, paths.serviceName); err != nil {
		return "", fmt.Errorf("failed to write logrotate file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to reload systemd: %v", err)
	}

	if paths.isLegacy {
		logLegacyWarning(name)
	}

	log.Info().Msgf("Successfully installed systemd service '%s'", paths.serviceName)
	log.Info().Msgf("To start the service, run: sudo systemctl start %s", paths.serviceName)
	log.Info().Msgf("To enable the service on boot, run: sudo systemctl enable %s", paths.serviceName)

	return paths.serviceName, nil
}

// InstallAwsAuthGatewaySystemdService installs the systemd service for a gateway using AWS Auth.
// Unlike the token-auth flow, no JWT is written into the env file — the gateway performs a
// fresh STS-signed login on each service start using whatever AWS credentials it can resolve
// (instance role, env vars, shared profile). We just persist the gateway id, domain, and name
// so `gateway start` can re-authenticate.
func InstallAwsAuthGatewaySystemdService(gatewayID string, domain string, name string, relayName string, serviceLogFile string) (string, error) {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return "", nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return "", nil
	}

	paths := resolveInstallPaths(name)

	if err := os.MkdirAll(filepath.Dir(paths.configPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	configContent := fmt.Sprintf("%s=%s\n", INFISICAL_GATEWAY_ID_KEY, gatewayID)
	configContent += "INFISICAL_GATEWAY_ENROLL_METHOD=aws\n"
	if domain != "" {
		configContent += fmt.Sprintf("INFISICAL_API_URL=%s\n", domain)
	}
	if name != "" {
		configContent += fmt.Sprintf("%s=%s\n", GATEWAY_NAME_ENV_NAME, name)
	}
	if relayName != "" {
		configContent += fmt.Sprintf("%s=%s\n", RELAY_NAME_ENV_NAME, relayName)
	}

	if err := os.WriteFile(paths.configPath, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write environment file: %v", err)
	}

	if err := util.WriteSystemdServiceFile(serviceLogFile, paths.configPath, paths.serviceName, "gateway", fmt.Sprintf("Infisical Gateway Service (%s)", name)); err != nil {
		return "", fmt.Errorf("failed to write systemd service file: %v", err)
	}

	if err := util.WriteLogrotateFile(serviceLogFile, paths.serviceName); err != nil {
		return "", fmt.Errorf("failed to write logrotate file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to reload systemd: %v", err)
	}

	if paths.isLegacy {
		logLegacyWarning(name)
	}

	log.Info().Msgf("Successfully installed systemd service '%s'", paths.serviceName)
	log.Info().Msgf("To start the service, run: sudo systemctl start %s", paths.serviceName)
	log.Info().Msgf("To enable the service on boot, run: sudo systemctl enable %s", paths.serviceName)

	return paths.serviceName, nil
}

func UninstallGatewaySystemdService(name string) error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service uninstallation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service uninstallation - not running as root/sudo")
		return nil
	}

	namedServicePath := serviceFilePath(name)
	svcName := serviceName(name)
	configPath := gatewayConfigPath(name)
	isLegacy := false

	if _, err := os.Stat(namedServicePath); os.IsNotExist(err) {
		legacy := detectLegacyService()
		if !legacy.exists || legacy.gatewayName != name {
			return fmt.Errorf("no gateway service found for '%s'", name)
		}
		svcName = legacyServiceName
		configPath = legacyConfigPath
		isLegacy = true
		log.Warn().Msgf("Removing legacy service '%s' for gateway '%s'", legacyServiceName, name)
	}

	stopCmd := exec.Command("systemctl", "stop", svcName)
	if err := stopCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to stop service: %v", err)
	}

	disableCmd := exec.Command("systemctl", "disable", svcName)
	if err := disableCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to disable service: %v", err)
	}

	svcFilePath := namedServicePath
	if isLegacy {
		svcFilePath = legacyServicePath
	}
	if err := os.Remove(svcFilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd service file: %v", err)
	}

	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msgf("Successfully uninstalled gateway service '%s'", svcName)
	return nil
}
