package kmip

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog/log"
)

const systemdServiceTemplate = `[Unit]
Description=Infisical KMIP Server Service
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/infisical/kmip.conf
ExecStart=infisical kmip start
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

func InstallKmipSystemdService(clientId, clientSecret, domain, listenAddress, serverName, certificateTTL, hostnamesOrIps string) error {
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

	configContent := fmt.Sprintf("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID=%s\n", clientId)
	configContent += fmt.Sprintf("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=%s\n", clientSecret)

	if domain != "" {
		configContent += fmt.Sprintf("INFISICAL_API_URL=%s\n", domain)
	}
	if listenAddress != "" {
		configContent += fmt.Sprintf("INFISICAL_KMIP_LISTEN_ADDRESS=%s\n", listenAddress)
	}
	if serverName != "" {
		configContent += fmt.Sprintf("INFISICAL_KMIP_SERVER_NAME=%s\n", serverName)
	}
	if certificateTTL != "" {
		configContent += fmt.Sprintf("INFISICAL_KMIP_CERTIFICATE_TTL=%s\n", certificateTTL)
	}
	if hostnamesOrIps != "" {
		configContent += fmt.Sprintf("INFISICAL_KMIP_HOSTNAMES_OR_IPS=%s\n", hostnamesOrIps)
	}

	configPath := filepath.Join(configDir, "kmip.conf")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	servicePath := "/etc/systemd/system/infisical-kmip.service"
	if err := os.WriteFile(servicePath, []byte(systemdServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	return nil
}

func UninstallKmipSystemdService() error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service uninstallation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service uninstallation - not running as root/sudo")
		return nil
	}

	// Stop the service if it's running
	stopCmd := exec.Command("systemctl", "stop", "infisical-kmip")
	if err := stopCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to stop service: %v", err)
	}

	// Disable the service
	disableCmd := exec.Command("systemctl", "disable", "infisical-kmip")
	if err := disableCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to disable service: %v", err)
	}

	// Remove the service file
	servicePath := "/etc/systemd/system/infisical-kmip.service"
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd service file: %v", err)
	}

	// Remove the configuration file
	configPath := "/etc/infisical/kmip.conf"
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %v", err)
	}

	// Reload systemd to apply changes
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully uninstalled Infisical KMIP systemd service")
	return nil
}
