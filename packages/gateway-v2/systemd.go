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

func InstallGatewaySystemdService(token string, domain string, name string, relayName string, serviceLogFile string) error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return nil
	}

	configDir := "/etc/infisical"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
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

	environmentFilePath := filepath.Join(configDir, "gateway.conf")
	if err := os.WriteFile(environmentFilePath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write environment file: %v", err)
	}

	if err := util.WriteSystemdServiceFile(serviceLogFile, environmentFilePath, "infisical-gateway"); err != nil {
		return fmt.Errorf("failed to write systemd service file: %v", err)
	}

	if err := util.WriteLogrotateFile(serviceLogFile, "infisical-gateway"); err != nil {
		return fmt.Errorf("failed to write logrotate file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully installed systemd service")
	log.Info().Msg("To start the service, run: sudo systemctl start infisical-gateway")
	log.Info().Msg("To enable the service on boot, run: sudo systemctl enable infisical-gateway")

	return nil
}

func UninstallGatewaySystemdService() error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service uninstallation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service uninstallation - not running as root/sudo")
		return nil
	}

	// Stop the service if it's running
	stopCmd := exec.Command("systemctl", "stop", "infisical-gateway")
	if err := stopCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to stop service: %v", err)
	}

	// Disable the service
	disableCmd := exec.Command("systemctl", "disable", "infisical-gateway")
	if err := disableCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to disable service: %v", err)
	}

	// Remove the service file
	servicePath := "/etc/systemd/system/infisical-gateway.service"
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd service file: %v", err)
	}

	// Remove the configuration file
	configPath := "/etc/infisical/gateway.conf"
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %v", err)
	}

	// Reload systemd to apply changes
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully uninstalled Infisical Gateway systemd service")
	return nil
}
