package relay

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"text/template"

	gatewayv2 "github.com/Infisical/infisical-merge/packages/gateway-v2"
	"github.com/Infisical/infisical-merge/packages/templates"
	"github.com/rs/zerolog/log"
)

// InstallRelaySystemdService installs the systemd unit and writes configuration for the relay.
// token is used for org-type relays (written as INFISICAL_TOKEN). For instance-type relays,
// relayAuthSecret is written as INFISICAL_RELAY_AUTH_SECRET.
func InstallRelaySystemdService(token string, domain string, name string, host string, instanceType string, relayAuthSecret string, serviceLogFile string) error {
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

	configPath := filepath.Join(configDir, "relay.conf")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	tmpl, err := template.ParseFS(templates.TemplatesFS, "infisical-service.tmpl")
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	data := map[string]string{
		"Description":     "Infisical Relay Service",
		"EnvironmentFile": configPath,
		"ServiceType":     "relay",
	}

	if serviceLogFile != "" {

		serviceLogFile = filepath.Clean(serviceLogFile)

		if !filepath.IsAbs(serviceLogFile) {
			return fmt.Errorf("service-log-file must be an absolute path: %s", serviceLogFile)
		}

		logDir := filepath.Dir(serviceLogFile)

		// create the directory structure with appropriate permissions
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory %s: %w", logDir, err)
		}

		// create the log file if it doesn't exist
		logFile, err := os.Create(serviceLogFile)
		if err != nil {
			return fmt.Errorf("failed to create log file %s: %w", serviceLogFile, err)
		}
		logFile.Close()

		data["ServiceLogFile"] = serviceLogFile
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	servicePath := "/etc/systemd/system/infisical-relay.service"
	if err := os.WriteFile(servicePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully installed systemd service for Infisical Relay")
	log.Info().Msg("To start the service, run: sudo systemctl start infisical-relay")
	log.Info().Msg("To enable the service on boot, run: sudo systemctl enable infisical-relay")

	return nil
}

func UninstallRelaySystemdService() error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service uninstallation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service uninstallation - not running as root/sudo")
		return nil
	}

	// Stop the service if it's running
	stopCmd := exec.Command("systemctl", "stop", "infisical-relay")
	if err := stopCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to stop service: %v", err)
	}

	// Disable the service
	disableCmd := exec.Command("systemctl", "disable", "infisical-relay")
	if err := disableCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to disable service: %v", err)
	}

	// Remove the service file
	servicePath := "/etc/systemd/system/infisical-relay.service"
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd service file: %v", err)
	}

	// Remove the configuration file
	configPath := "/etc/infisical/relay.conf"
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %v", err)
	}

	// Reload systemd to apply changes
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msg("Successfully uninstalled Infisical Relay systemd service")
	return nil
}
