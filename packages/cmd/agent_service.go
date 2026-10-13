package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Infisical/infisical-merge/packages/templates"
	"github.com/Infisical/infisical-merge/packages/util"
)

// The platform specific halves live in agent_service_systemd.go (Linux) and agent_service_windows.go
// (Windows Service Control Manager). Each one provides:
//
//	checkAgentServiceSupport() error
//	defaultAgentServiceLogFile(name string) string
//	installAgentService(opts agentServiceOptions) error
//	uninstallAgentService(name string) error
//	startAgentService(name string) error
//	stopAgentService(name string) error
//	runAgentAsWindowsService(configPath, logFile string) (isService bool, exitCode int)

const defaultAgentServiceName = "infisical-agent"

// agentServiceMarker is written into the unit files the CLI installs, so that uninstall, start and stop
// refuse to touch a service some other tool created.
const agentServiceMarker = "Installed by 'infisical agent service install'"

var agentServiceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// agentServiceOptions describes an agent service the way the platform's service manager runs it.
type agentServiceOptions struct {
	Name       string
	Executable string // absolute path of the infisical binary the service runs
	ConfigPath string // absolute path of the agent config
	LogFile    string // absolute path of the agent log file, empty to log only to the service manager
}

// args returns the command line arguments the service manager starts the agent with.
func (o agentServiceOptions) args() []string {
	args := []string{"agent", "--config", o.ConfigPath}
	if o.LogFile != "" {
		args = append(args, "--log-file", o.LogFile)
	}
	return args
}

func newAgentServiceOptions(name, configPath, logFile string) (agentServiceOptions, error) {
	if err := validateAgentServiceName(name); err != nil {
		return agentServiceOptions{}, err
	}

	// the service manager does not start the agent from the current directory, so store absolute paths
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return agentServiceOptions{}, fmt.Errorf("unable to resolve the config path: %w", err)
	}

	if err := validateAgentServiceConfig(configPath); err != nil {
		return agentServiceOptions{}, err
	}

	if logFile == "" {
		logFile = defaultAgentServiceLogFile(name)
	}
	if logFile != "" {
		if logFile, err = filepath.Abs(logFile); err != nil {
			return agentServiceOptions{}, fmt.Errorf("unable to resolve the log file path: %w", err)
		}
	}

	executable, err := os.Executable()
	if err != nil {
		return agentServiceOptions{}, fmt.Errorf("unable to locate the infisical binary: %w", err)
	}

	for _, path := range []string{executable, configPath, logFile} {
		if strings.ContainsAny(path, "\r\n") {
			return agentServiceOptions{}, fmt.Errorf("the path %q contains a line break, which a service definition cannot hold", path)
		}
	}

	return agentServiceOptions{
		Name:       name,
		Executable: executable,
		ConfigPath: configPath,
		LogFile:    logFile,
	}, nil
}

func validateAgentServiceName(name string) error {
	if !agentServiceNamePattern.MatchString(name) {
		return fmt.Errorf("invalid service name %q: use up to 128 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	return nil
}

// validateAgentServiceConfig reports config errors at install time rather than on the service's first start.
func validateAgentServiceConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("unable to read the agent config: %w", err)
	}

	agentConfig, err := ParseAgentConfig(data)
	if err != nil {
		return fmt.Errorf("unable to parse the agent config at %s: %w", configPath, err)
	}

	if valid, _ := util.IsAuthMethodValid(agentConfig.Auth.Type, false); !valid {
		return fmt.Errorf("the auth method '%s' in %s is not supported", agentConfig.Auth.Type, configPath)
	}

	if agentConfig.Infisical.ExitAfterAuth {
		return fmt.Errorf("%s sets 'exit-after-auth: true', so the agent would exit after its first render and the service would keep being restarted. Remove it to run the agent as a service", configPath)
	}

	return nil
}

func agentServiceDisplayName(name string) string {
	return fmt.Sprintf("Infisical Agent (%s)", name)
}

// renderAgentSystemdUnit returns the systemd unit file for an agent service.
func renderAgentSystemdUnit(opts agentServiceOptions) (string, error) {
	tmpl, err := template.ParseFS(templates.TemplatesFS, "infisical-agent-service.tmpl")
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var execStart []string
	for _, arg := range append([]string{opts.Executable}, opts.args()...) {
		execStart = append(execStart, systemdQuoteArg(arg))
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]string{
		"Marker":      agentServiceMarker,
		"Name":        opts.Name,
		"Description": agentServiceDisplayName(opts.Name),
		"ExecStart":   strings.Join(execStart, " "),
		// relative paths in the agent config resolve from the directory that holds it
		"WorkingDirectory": strings.ReplaceAll(filepath.Dir(opts.ConfigPath), "%", "%%"),
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// systemdQuoteArg escapes one command line argument for a unit file's ExecStart=.
func systemdQuoteArg(arg string) string {
	// systemd expands %-specifiers and $VARIABLES in ExecStart=
	arg = strings.ReplaceAll(arg, "%", "%%")
	arg = strings.ReplaceAll(arg, "$", "$$")

	if arg != "" && !strings.ContainsAny(arg, " \t\"'\\;") {
		return arg
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(arg) + `"`
}

// setAgentLogOutput sends agent logs to logFile (rotated by size), to the usual log stream when
// includeStream is set, and to any extra writers.
func setAgentLogOutput(logFile string, includeStream bool, extra ...io.Writer) {
	format := resolveLogFormat()

	var writers []io.Writer
	if logFile != "" {
		// keep ANSI colors out of the file
		fileFormat := "plain"
		if format == "json" {
			fileFormat = "json"
		}

		writers = append(writers, formatLogWriter(&lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    100, // megabytes
			MaxBackups: 5,
			Compress:   true,
		}, fileFormat))
	}

	if includeStream {
		writers = append(writers, formatLogWriter(resolveLogDestination(), format))
	}

	writers = append(writers, extra...)

	log.Logger = log.Output(zerolog.MultiLevelWriter(writers...))
}

func agentServiceNameFromArgs(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return defaultAgentServiceName
}

var agentServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Run the agent as a background service (systemd on Linux, a Windows service on Windows)",
	Long: `Install, start, stop and uninstall the agent as a service. On Linux it is a systemd unit, on Windows a service registered with the Service Control Manager. The service starts on boot and is restarted when it fails.

The service is named infisical-agent unless you pass a name, so several agents with different configs can run on one machine. Relative paths in the agent config are resolved from the directory that holds the config file.`,
	Example: `  sudo infisical agent service install --config /etc/infisical/agent-config.yaml
  sudo infisical agent service start

  # On Windows, from an elevated prompt (Run as administrator)
  infisical agent service install --config C:\infisical\agent-config.yaml
  infisical agent service start`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var agentServiceInstallCmd = &cobra.Command{
	Use:   "install [name]",
	Short: "Install the agent as a service that starts on boot (requires root or Administrator)",
	Long:  "Install the agent as a service that starts on boot and restarts when it fails. The config is checked before the service is created. Requires root (sudo) on Linux and an elevated prompt on Windows. The service is not started; run 'infisical agent service start' afterwards.",
	Example: `  sudo infisical agent service install --config /etc/infisical/agent-config.yaml
  sudo infisical agent service install chef-secrets --config /etc/infisical/chef.yaml --log-file /var/log/infisical/chef-secrets.log
  infisical agent service install --config C:\infisical\agent-config.yaml`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkAgentServiceSupport(); err != nil {
			util.HandleError(err)
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			util.HandleError(err, "Unable to parse flag config")
		}

		logFile, err := cmd.Flags().GetString("log-file")
		if err != nil {
			util.HandleError(err, "Unable to parse flag log-file")
		}

		opts, err := newAgentServiceOptions(agentServiceNameFromArgs(args), configPath, logFile)
		if err != nil {
			util.HandleError(err, "Unable to install the agent service")
		}

		if opts.LogFile != "" {
			// create the directory now, so a path the service cannot write to fails here and not silently later
			if err := os.MkdirAll(filepath.Dir(opts.LogFile), 0o755); err != nil {
				util.HandleError(err, "Unable to create the log file directory")
			}
		}

		if err := installAgentService(opts); err != nil {
			util.HandleError(err, "Unable to install the agent service")
		}
	},
}

// newAgentServiceActionCmd builds the uninstall, start and stop commands, which differ only in what they run.
func newAgentServiceActionCmd(action string, short string, run func(name string) error) *cobra.Command {
	return &cobra.Command{
		Use:                   action + " [name]",
		Short:                 short,
		Example:               fmt.Sprintf("  sudo infisical agent service %s\n  sudo infisical agent service %s chef-secrets", action, action),
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := checkAgentServiceSupport(); err != nil {
				util.HandleError(err)
			}

			name := agentServiceNameFromArgs(args)
			if err := validateAgentServiceName(name); err != nil {
				util.HandleError(err)
			}

			if err := run(name); err != nil {
				util.HandleError(err, fmt.Sprintf("Unable to %s the agent service", action))
			}
		},
	}
}

func init() {
	agentServiceInstallCmd.Flags().String("config", "agent-config.yaml", "The path to the agent config yaml file the service runs with")
	agentServiceInstallCmd.Flags().String("log-file", "", `The file the service writes agent logs to, rotated once it reaches 100MB. Defaults to %ProgramData%\Infisical\Agent\<name>.log on Windows. On Linux logs always go to the systemd journal (journalctl -u <name>), and to this file as well when it is set`)

	agentServiceCmd.AddCommand(agentServiceInstallCmd)
	agentServiceCmd.AddCommand(newAgentServiceActionCmd("uninstall", "Stop and remove the agent service (requires root or Administrator)", uninstallAgentService))
	agentServiceCmd.AddCommand(newAgentServiceActionCmd("start", "Start the agent service (requires root or Administrator)", startAgentService))
	agentServiceCmd.AddCommand(newAgentServiceActionCmd("stop", "Stop the agent service (requires root or Administrator)", stopAgentService))

	agentCmd.AddCommand(agentServiceCmd)
}
