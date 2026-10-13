//go:build !windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
)

const agentSystemdUnitDir = "/etc/systemd/system"

func agentSystemdUnitPath(name string) string {
	return filepath.Join(agentSystemdUnitDir, name+".service")
}

func checkAgentServiceSupport() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("running the agent as a service is supported on Linux (systemd) and Windows, not on %s", runtime.GOOS)
	}

	if os.Geteuid() != 0 {
		return errors.New("managing the agent service requires root, re-run the command with sudo")
	}

	// systemd creates this directory when it is the init system
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is not running on this machine")
	}

	return nil
}

// defaultAgentServiceLogFile returns no file: on Linux the systemd journal already keeps the agent's logs.
func defaultAgentServiceLogFile(name string) string {
	return ""
}

func installAgentService(opts agentServiceOptions) error {
	unitPath := agentSystemdUnitPath(opts.Name)
	if _, err := os.Stat(unitPath); err == nil {
		return fmt.Errorf("%s already exists. To replace it, first run: sudo infisical agent service uninstall %s", unitPath, opts.Name)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("unable to check %s: %w", unitPath, err)
	}

	unit, err := renderAgentSystemdUnit(opts)
	if err != nil {
		return err
	}

	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("unable to write %s: %w", unitPath, err)
	}

	if err := systemctl("daemon-reload"); err != nil {
		return err
	}

	if err := systemctl("enable", opts.Name); err != nil {
		return err
	}

	log.Info().Msgf("Installed and enabled the %s service (%s)", opts.Name, unitPath)
	log.Info().Msgf("Start it with: sudo infisical agent service start %s", opts.Name)
	return nil
}

func uninstallAgentService(name string) error {
	unitPath, err := managedAgentUnitPath(name)
	if err != nil {
		return err
	}

	if err := systemctl("stop", name); err != nil {
		log.Warn().Msgf("unable to stop the %s service: %v", name, err)
	}

	if err := systemctl("disable", name); err != nil {
		log.Warn().Msgf("unable to disable the %s service: %v", name, err)
	}

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to remove %s: %w", unitPath, err)
	}

	if err := systemctl("daemon-reload"); err != nil {
		return err
	}

	log.Info().Msgf("Uninstalled the %s service", name)
	return nil
}

func startAgentService(name string) error {
	if _, err := managedAgentUnitPath(name); err != nil {
		return err
	}

	// the unit is Type=notify, so this returns once the agent has loaded its config, or fails if it could not
	if err := systemctl("start", name); err != nil {
		return fmt.Errorf("%w\nSee the agent's logs with: journalctl -u %s", err, name)
	}

	log.Info().Msgf("Started the %s service. Follow its logs with: journalctl -u %s -f", name, name)
	return nil
}

func stopAgentService(name string) error {
	if _, err := managedAgentUnitPath(name); err != nil {
		return err
	}

	if err := systemctl("stop", name); err != nil {
		return err
	}

	log.Info().Msgf("Stopped the %s service", name)
	return nil
}

// managedAgentUnitPath returns the unit file of an installed agent service, refusing units that
// 'infisical agent service install' did not write.
func managedAgentUnitPath(name string) (string, error) {
	unitPath := agentSystemdUnitPath(name)

	unit, err := os.ReadFile(unitPath)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("no agent service named %s is installed (%s does not exist)", name, unitPath)
	}
	if err != nil {
		return "", fmt.Errorf("unable to read %s: %w", unitPath, err)
	}

	if !strings.Contains(string(unit), agentServiceMarker) {
		return "", fmt.Errorf("%s was not installed by 'infisical agent service install', refusing to manage it", unitPath)
	}

	return unitPath, nil
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runAgentAsWindowsService never applies outside Windows.
func runAgentAsWindowsService(configPath, logFile string) (bool, int) {
	return false, 0
}
