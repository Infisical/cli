package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

// ConfigPathEnvName tells `infisical agent start` which config to run. The systemd environment file sets it.
const ConfigPathEnvName = "INFISICAL_AGENT_CONFIG_PATH"

// WorkingDirEnvName is the directory relative paths in a service's config resolve from. A service runs a copy of its
// config, so install sets it to the original config's directory.
const WorkingDirEnvName = "INFISICAL_AGENT_WORKING_DIR"

const agentsConfigDir = "/etc/infisical/agents"

// UnitName returns the systemd unit of an agent. systemctl gets the full unit name, so a name that itself ends in
// a unit suffix (e.g. app.service) cannot make it act on a different unit.
func UnitName(name string) string {
	return name + ".service"
}

// agentServiceFilePath returns the systemd unit path for an agent with the given name.
func agentServiceFilePath(name string) string {
	return filepath.Join("/etc/systemd/system", UnitName(name))
}

// agentEnvFilePath returns the systemd environment file path for an agent.
func agentEnvFilePath(name string) string {
	return filepath.Join(agentsConfigDir, name+".env.conf")
}

// agentConfigCopyPath returns the copy of its config an agent service runs.
func agentConfigCopyPath(name string) string {
	return filepath.Join(agentsConfigDir, name+".service-config.yaml")
}

// CheckPathsVisibleToSystemd fails for paths an agent run by the shared systemd unit cannot use: the unit makes
// /home inaccessible and gives the service its own /tmp and /var/tmp.
func CheckPathsVisibleToSystemd(paths []string) error {
	for _, path := range paths {
		clean := filepath.Clean(path)
		for _, hidden := range []string{"/home", "/tmp", "/var/tmp"} {
			if clean == hidden || strings.HasPrefix(clean, hidden+"/") {
				return fmt.Errorf("%s is under %s, which the agent's systemd service cannot access. Move it, e.g. to %s", path, hidden, agentsConfigDir)
			}
		}
	}
	return nil
}

// EnsureAgentSystemdService fails unless name is a service installed by `infisical agent service install`
// (only those have an agent environment file), so start, stop and uninstall never touch other units.
func EnsureAgentSystemdService(name string) error {
	if _, err := os.Stat(agentServiceFilePath(name)); os.IsNotExist(err) {
		return fmt.Errorf("no agent service found for '%s'", name)
	}
	if _, err := os.Stat(agentEnvFilePath(name)); os.IsNotExist(err) {
		return fmt.Errorf("'%s' was not installed by 'infisical agent service install', refusing to manage it", name)
	}
	return nil
}

// InstallAgentSystemdService installs the systemd unit for an agent that runs configData, read from configPath. The
// service is named after the agent, so several agents can run on the same machine. It logs to the systemd journal
// (journalctl -u <name>), which only root can read by default: debug logs include rendered secrets.
func InstallAgentSystemdService(name string, configPath string, configData []byte) (string, error) {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service installation - not on Linux")
		return "", nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service installation - not running as root/sudo")
		return "", nil
	}

	// systemd loads units from several directories (/etc, /run, /usr/lib/systemd/system, ...), so ask it whether the
	// name is taken: a unit written to /etc/systemd/system would override a system service such as cron
	out, err := exec.Command("systemctl", "show", "-p", "LoadState", UnitName(name)).Output()
	if err != nil {
		return "", fmt.Errorf("failed to check for an existing '%s' unit: %v", name, err)
	}
	if strings.TrimSpace(string(out)) != "LoadState=not-found" {
		return "", fmt.Errorf("a systemd unit named '%s' already exists. Pick another name, or if 'infisical agent service install' created it, uninstall it first with: sudo infisical agent service uninstall %s", name, name)
	}

	if err := os.MkdirAll(agentsConfigDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	// the service runs as root and its config can run commands, so it runs its own copy that only root can change: a
	// user who can edit the original, or still has it open from before, cannot change what the service runs
	if err := os.WriteFile(agentConfigCopyPath(name), configData, 0600); err != nil {
		return "", fmt.Errorf("failed to write the service's copy of the config: %v", err)
	}

	configContent := fmt.Sprintf("%s=%s\n%s=%s\n", ConfigPathEnvName, agentConfigCopyPath(name), WorkingDirEnvName, filepath.Dir(configPath))
	if err := os.WriteFile(agentEnvFilePath(name), []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("failed to write environment file: %v", err)
	}

	if err := util.WriteSystemdServiceFile("", agentEnvFilePath(name), name, "agent", fmt.Sprintf("Infisical Agent Service (%s)", name)); err != nil {
		return "", fmt.Errorf("failed to write systemd service file: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msgf("Successfully installed systemd service '%s'", name)
	log.Info().Msgf("It runs a copy of %s that only root can change, %s: edit that copy and restart the service, or edit the original and install again", configPath, agentConfigCopyPath(name))
	return name, nil
}

// StartAgentSystemdService starts an agent service. The unit is Type=notify, so this returns once the agent has
// loaded its config and started, or fails if it could not.
func StartAgentSystemdService(name string) error {
	if err := EnsureAgentSystemdService(name); err != nil {
		return err
	}

	if out, err := exec.Command("systemctl", "start", UnitName(name)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start '%s': %v: %s. See its logs with: journalctl -u %s", name, err, strings.TrimSpace(string(out)), name)
	}

	log.Info().Msgf("Started the '%s' service. Follow its logs with: journalctl -u %s -f", name, name)
	return nil
}

// StopAgentSystemdService stops an agent service.
func StopAgentSystemdService(name string) error {
	if err := EnsureAgentSystemdService(name); err != nil {
		return err
	}

	if out, err := exec.Command("systemctl", "stop", UnitName(name)).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop '%s': %v: %s", name, err, strings.TrimSpace(string(out)))
	}

	log.Info().Msgf("Stopped the '%s' service", name)
	return nil
}

// UninstallAgentSystemdService stops and removes an agent service, with its environment file and config copy.
func UninstallAgentSystemdService(name string) error {
	if runtime.GOOS != "linux" {
		log.Info().Msg("Skipping systemd service uninstallation - not on Linux")
		return nil
	}

	if os.Geteuid() != 0 {
		log.Info().Msg("Skipping systemd service uninstallation - not running as root/sudo")
		return nil
	}

	if err := EnsureAgentSystemdService(name); err != nil {
		return err
	}

	// Stop the service first: removing its files would not stop an agent that is still running
	stopCmd := exec.Command("systemctl", "stop", UnitName(name))
	if err := stopCmd.Run(); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	// Disable the service
	disableCmd := exec.Command("systemctl", "disable", UnitName(name))
	if err := disableCmd.Run(); err != nil {
		log.Warn().Msgf("Failed to disable service: %v", err)
	}

	// Remove the service file
	if err := os.Remove(agentServiceFilePath(name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove systemd service file: %v", err)
	}

	// Remove the systemd environment file and the service's copy of the config
	for _, path := range []string{agentEnvFilePath(name), agentConfigCopyPath(name)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %v", path, err)
		}
	}

	// Reload systemd to apply changes
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	log.Info().Msgf("Successfully uninstalled Infisical Agent systemd service '%s'", name)
	return nil
}
