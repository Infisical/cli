package connector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog/log"
)

const systemdServiceTemplate = `[Unit]
Description=Infisical Connector Service
After=network.target

[Service]
Type=notify
NotifyAccess=all
EnvironmentFile=/etc/infisical/connector.conf
ExecStart=infisical connector start
Restart=on-failure
InaccessibleDirectories=/home
PrivateTmp=yes
LimitCORE=infinity
LimitNOFILE=1000000
LimitNPROC=60000
LimitRTPRIO=infinity
LimitRTTIME=7000000

[Install]
WantedBy=multi-user.target
`

func InstallConnectorSystemdService(token string, domain string, name string, relayName string) error {
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
		configContent += fmt.Sprintf("%s=%s\n", CONNECTOR_NAME_ENV_NAME, name)
	}
	if relayName != "" {
		configContent += fmt.Sprintf("%s=%s\n", RELAY_NAME_ENV_NAME, relayName)
	}

	configPath := filepath.Join(configDir, "connector.conf")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	servicePath := "/etc/systemd/system/infisical-connector.service"
	if err := os.WriteFile(servicePath, []byte(systemdServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully installed systemd service")
	log.Info().Msg("To start the service, run: sudo systemctl start infisical-connector")
	log.Info().Msg("To enable the service on boot, run: sudo systemctl enable infisical-connector")

	return nil
}

func UninstallConnectorSystemdService() error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service uninstallation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service uninstallation - not running as root/sudo")
		return nil
	}

	// Stop the service if it's running
	stopCmd := exec.Command("systemctl", "stop", "infisical-connector")
	if err := stopCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to stop service: %v", err)
	}

	// Disable the service
	disableCmd := exec.Command("systemctl", "disable", "infisical-connector")
	if err := disableCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to disable service: %v", err)
	}

	// Remove the service file
	servicePath := "/etc/systemd/system/infisical-connector.service"
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd service file: %v", err)
	}

	// Remove the configuration file
	configPath := "/etc/infisical/connector.conf"
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %v", err)
	}

	// Reload systemd to apply changes
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully uninstalled Infisical Connector systemd service")
	return nil
}
