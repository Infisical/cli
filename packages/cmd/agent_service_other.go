//go:build !windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/Infisical/infisical-merge/packages/agent"
	"github.com/rs/zerolog/log"
)

// Outside Windows, 'agent service' manages a systemd service (see packages/agent/systemd.go), so it needs Linux.

// runAgentAsWindowsService never applies outside Windows.
func runAgentAsWindowsService(configPath string) (bool, int) {
	return false, 0
}

func checkAgentServiceSupport() error {
	if runtime.GOOS != "linux" {
		return errors.New("running the agent as a service is supported on Linux (systemd) and Windows")
	}
	if os.Geteuid() != 0 {
		return errors.New("managing the agent service requires root, re-run the command with sudo")
	}
	return nil
}

var (
	uninstallAgentService = agent.UninstallAgentSystemdService
	startAgentService     = agent.StartAgentSystemdService
	stopAgentService      = agent.StopAgentSystemdService
)

// installAgentService installs and enables a systemd service for the agent.
func installAgentService(name, configPath string) error {
	// the service does not start the agent from the current directory, so store an absolute path
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("unable to resolve the config path: %w", err)
	}

	configData, agentConfig, err := readAgentServiceConfig(configPath)
	if err != nil {
		return err
	}

	if err := agent.CheckPathsVisibleToSystemd(agentSystemdPaths(configPath, agentConfig)); err != nil {
		return err
	}

	installedServiceName, err := agent.InstallAgentSystemdService(name, configPath, configData)
	if err != nil {
		return err
	}

	if err := exec.Command("systemctl", "enable", agent.UnitName(installedServiceName)).Run(); err != nil {
		return fmt.Errorf("failed to enable the service: %w", err)
	}

	log.Info().Msgf("Successfully installed and enabled %s service", installedServiceName)
	log.Info().Msgf("To start the service, run: sudo infisical agent service start %s", installedServiceName)
	log.Info().Msgf("Its logs go to the systemd journal: sudo journalctl -u %s", installedServiceName)
	return nil
}

// agentSystemdPaths returns the files a systemd-run agent reads or writes (its config, credential files, cache,
// template sources and destinations, token sinks), with relative paths resolved from the config's directory, as
// `agent start` does.
func agentSystemdPaths(configPath string, agentConfig *Config) []string {
	paths := []string{configPath}
	add := func(path string) {
		if path == "" {
			return
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(configPath), path)
		}
		paths = append(paths, path)
	}
	// every text setting of an auth method is a file the agent reads (client id and secret, identity id, tokens, keys)
	if authSettings, ok := agentConfig.Auth.Config.(map[interface{}]interface{}); ok {
		for _, setting := range authSettings {
			if path, isText := setting.(string); isText {
				add(path)
			}
		}
	}
	if agentConfig.Cache.Persistent != nil {
		add(agentConfig.Cache.Persistent.Path)
		add(agentConfig.Cache.Persistent.ServiceAccountTokenPath)
	}
	for _, template := range agentConfig.Templates {
		add(template.SourcePath)
		add(template.DestinationPath)
	}
	for _, sink := range agentConfig.Sinks {
		add(sink.Config.Path)
	}
	return paths
}
