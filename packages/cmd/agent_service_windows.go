//go:build windows

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/Infisical/infisical-merge/packages/util"
)

const defaultAgentServiceName = "infisical-agent"

// the agent writes every Event Log entry under one id; the message carries the detail
const agentEventLogID = 1

// how long the SCM should wait between status updates while the agent starts or stops
const agentServiceWaitHint = 30 * time.Second

var agentServiceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// the service name becomes a file name (<name>.log), and Windows reserves these device names, with or without an extension
var windowsReservedNamePattern = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)`)

// agentServiceMarker is written into the service description, so that uninstall, start and stop
// refuse to touch a service some other tool created
const agentServiceMarker = "Installed by 'infisical agent service install'"

// only SYSTEM and Administrators may access what a LocalSystem service runs, obeys or logs (logs can hold
// secret values at debug level), and Administrators own it, so a standard user can neither change it nor
// take it over; OICI makes new files in a directory, such as rotated logs, inherit it
const agentServiceAdminOnlySDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func restrictToAdministrators(path string) error {
	sd, err := windows.SecurityDescriptorFromString(agentServiceAdminOnlySDDL)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}

// readAgentServiceConfig reads the config, refusing one that Administrators or SYSTEM do not own: install hands the
// config to Administrators, so any other owner means it was replaced, e.g. by a standard user renaming a folder above
// it. The owner is checked on the same open file the config is read from, so it cannot be swapped in between.
func readAgentServiceConfig(configPath string) ([]byte, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open the agent config: %w", err)
	}
	defer file.Close()

	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("unable to read the owner of %s: %w", configPath, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("unable to read the owner of %s: %w", configPath, err)
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return nil, fmt.Errorf("%s is owned by %s rather than Administrators, so it may have been replaced and the agent will not run it. Check the file, then run 'infisical agent service uninstall' and 'install' again", configPath, owner)
	}

	return io.ReadAll(file)
}

// agentServiceDir holds a service's own copy of infisical.exe
func agentServiceDir(name string) string {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	return filepath.Join(programFiles, "Infisical", "Agent", name)
}

// copyAgentServiceExecutable copies infisical.exe into a folder only Administrators can change and returns the copy.
// The service runs it as LocalSystem, so it must not run a binary from a folder a standard user can write to (npm, Scoop).
func copyAgentServiceExecutable(name, executable string) (string, error) {
	dir := agentServiceDir(name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := restrictToAdministrators(dir); err != nil {
		return "", err
	}

	target := filepath.Join(dir, "infisical.exe")
	if strings.EqualFold(filepath.Clean(executable), target) {
		return target, nil
	}

	source, err := os.Open(executable)
	if err != nil {
		return "", err
	}
	defer source.Close()

	copied, err := os.Create(target)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(copied, source); err != nil {
		copied.Close()
		return "", err
	}
	return target, copied.Close()
}

// agentServiceOptions describes an agent service the way the Service Control Manager runs it.
type agentServiceOptions struct {
	Name       string
	Executable string // absolute path of the infisical binary the service runs
	ConfigPath string // absolute path of the agent config
}

func newAgentServiceOptions(name, configPath string) (agentServiceOptions, error) {
	if err := validateAgentServiceName(name); err != nil {
		return agentServiceOptions{}, err
	}

	// the SCM does not start the agent from the current directory, so store an absolute path
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return agentServiceOptions{}, fmt.Errorf("unable to resolve the config path: %w", err)
	}

	if err := validateAgentServiceConfig(configPath); err != nil {
		return agentServiceOptions{}, err
	}

	executable, err := os.Executable()
	if err != nil {
		return agentServiceOptions{}, fmt.Errorf("unable to locate the infisical binary: %w", err)
	}

	return agentServiceOptions{Name: name, Executable: executable, ConfigPath: configPath}, nil
}

func validateAgentServiceName(name string) error {
	if !agentServiceNamePattern.MatchString(name) {
		return fmt.Errorf("invalid service name %q: use up to 128 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	if windowsReservedNamePattern.MatchString(name) {
		return fmt.Errorf("invalid service name %q: Windows reserves it as a device name", name)
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

// agentServiceLogFile returns the file a service logs to: a service has no console.
func agentServiceLogFile(name string) string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "Infisical", "Agent", name+".log")
}

// setAgentServiceLogOutput sends agent logs to the service's log file, rotated by size, and to any extra writers.
func setAgentServiceLogOutput(name string, extra ...io.Writer) {
	file := &lumberjack.Logger{
		Filename:   agentServiceLogFile(name),
		MaxSize:    100, // megabytes
		MaxBackups: 5,
		Compress:   true,
	}
	writers := append([]io.Writer{GetLoggerConfig(file, true)}, extra...)
	log.Logger = log.Output(zerolog.MultiLevelWriter(writers...))
}

func agentServiceNameFromArgs(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return defaultAgentServiceName
}

func checkAgentServiceAdministrator() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("managing the agent service requires Administrator rights, re-run the command from an elevated prompt (Run as administrator)")
	}
	return nil
}

var agentServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Run the agent as a Windows service",
	Long: `Install, start, stop and uninstall the agent as a Windows service. The service starts on boot, restarts when it fails, and logs to %ProgramData%\Infisical\Agent\<name>.log, with errors also written to the Windows Event Log.

The service is named infisical-agent unless you pass a name, so several agents with different configs can run on one machine. Relative paths in the agent config are resolved from the directory that holds the config file. Run these commands from an elevated prompt (Run as administrator).`,
	Example: `  infisical agent service install --config C:\infisical\agent-config.yaml
  infisical agent service start`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var agentServiceInstallCmd = &cobra.Command{
	Use:   "install [name]",
	Short: "Install the agent as a Windows service that starts on boot (requires Administrator)",
	Long:  "Install the agent as a Windows service that starts on boot and restarts when it fails. The service runs as LocalSystem, so it runs its own copy of infisical.exe from %ProgramFiles%\\Infisical\\Agent\\<name> (uninstall and install again to upgrade it) and the config is restricted to Administrators. The config is checked before the service is created. The service is not started; run 'infisical agent service start' afterwards.",
	Example: `  infisical agent service install --config C:\infisical\agent-config.yaml
  infisical agent service install chef-secrets --config C:\infisical\chef.yaml`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := checkAgentServiceAdministrator(); err != nil {
			util.HandleError(err)
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			util.HandleError(err, "Unable to parse flag config")
		}

		opts, err := newAgentServiceOptions(agentServiceNameFromArgs(args), configPath)
		if err != nil {
			util.HandleError(err, "Unable to install the agent service")
		}

		if err := installAgentService(opts); err != nil {
			util.HandleError(err, "Unable to install the agent service")
		}
	},
}

// newAgentServiceActionCmd builds the uninstall, start and stop commands, which differ only in what they run
// on the opened service.
func newAgentServiceActionCmd(action string, short string, run func(name string, s *mgr.Service) error) *cobra.Command {
	return &cobra.Command{
		Use:                   action + " [name]",
		Short:                 short,
		Example:               fmt.Sprintf("  infisical agent service %s\n  infisical agent service %s chef-secrets", action, action),
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := checkAgentServiceAdministrator(); err != nil {
				util.HandleError(err)
			}

			name := agentServiceNameFromArgs(args)
			if err := validateAgentServiceName(name); err != nil {
				util.HandleError(err)
			}

			m, s, err := openAgentWindowsService(name)
			if err != nil {
				util.HandleError(err, fmt.Sprintf("Unable to %s the agent service", action))
			}
			defer m.Disconnect()
			defer s.Close()

			if err := run(name, s); err != nil {
				util.HandleError(err, fmt.Sprintf("Unable to %s the agent service", action))
			}
		},
	}
}

func installAgentService(opts agentServiceOptions) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("unable to connect to the Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(opts.Name); err == nil {
		existing.Close()
		return fmt.Errorf("a service named %s already exists. To replace it, first run: infisical agent service uninstall %s", opts.Name, opts.Name)
	}

	executable, err := copyAgentServiceExecutable(opts.Name, opts.Executable)
	if err != nil {
		return fmt.Errorf("unable to copy infisical.exe into %s: %w", agentServiceDir(opts.Name), err)
	}

	// the config decides what the service runs (execute commands) and writes, so a standard user must not be able to change it
	if err := restrictToAdministrators(opts.ConfigPath); err != nil {
		return fmt.Errorf("unable to restrict access to %s to Administrators: %w", opts.ConfigPath, err)
	}
	logDir := filepath.Dir(agentServiceLogFile(opts.Name))
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("unable to create %s: %w", logDir, err)
	}
	if err := restrictToAdministrators(logDir); err != nil {
		return fmt.Errorf("unable to restrict access to %s to Administrators: %w", logDir, err)
	}

	s, err := m.CreateService(opts.Name, executable, mgr.Config{
		DisplayName: fmt.Sprintf("Infisical Agent (%s)", opts.Name),
		Description: "Authenticates with Infisical and keeps secrets, tokens and certificates on this machine up to date. " + agentServiceMarker + ".",
		StartType:   mgr.StartAutomatic,
	}, "agent", "--config", opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("unable to create the %s service: %w", opts.Name, err)
	}
	defer s.Close()

	// restart the agent when it crashes or stops on its own, backing off so a broken config does not restart it every few seconds
	resetPeriod := uint32((24 * time.Hour).Seconds())
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, resetPeriod); err != nil {
		return deleteIncompleteService(s, fmt.Errorf("unable to set the service's recovery actions: %w", err))
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return deleteIncompleteService(s, fmt.Errorf("unable to set the service's recovery actions: %w", err))
	}

	// lets the agent's errors show up in Event Viewer under the service name
	if err := eventlog.InstallAsEventCreate(opts.Name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		// a source left behind by an earlier install still works
		log.Debug().Msgf("unable to register the %s event log source: %v", opts.Name, err)
	}

	log.Info().Msgf("Installed the %s service. It starts automatically on boot and logs to %s", opts.Name, agentServiceLogFile(opts.Name))
	log.Info().Msgf("The service runs its own copy of infisical.exe from %s. To upgrade it, uninstall and install the service again", filepath.Dir(executable))
	log.Info().Msgf("Only Administrators can now change %s. Keep the templates and credential files it points to in folders only Administrators can change too", opts.ConfigPath)
	log.Info().Msgf("Start it now with: infisical agent service start %s", opts.Name)
	return nil
}

func deleteIncompleteService(s *mgr.Service, cause error) error {
	if err := s.Delete(); err != nil {
		return fmt.Errorf("%w (removing the incomplete service also failed: %v)", cause, err)
	}
	return cause
}

func uninstallAgentService(name string, s *mgr.Service) error {
	// Delete only marks the service for removal, it does not stop a running agent
	if err := stopWindowsService(s); err != nil {
		return err
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("unable to delete the %s service: %w", name, err)
	}

	if err := eventlog.Remove(name); err != nil {
		log.Debug().Msgf("unable to remove the %s event log source: %v", name, err)
	}

	// only the service's own copy of infisical.exe: the folder may also hold the config, templates or credentials,
	// so it is removed only once empty
	copied := filepath.Join(agentServiceDir(name), "infisical.exe")
	if err := os.Remove(copied); err != nil && !os.IsNotExist(err) {
		log.Warn().Msgf("unable to remove %s: %v", copied, err)
	}
	_ = os.Remove(agentServiceDir(name))

	log.Info().Msgf("Uninstalled the %s service", name)
	return nil
}

func startAgentService(name string, s *mgr.Service) error {
	if err := s.Start(); err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			log.Info().Msgf("The %s service is already running", name)
			return nil
		}
		return fmt.Errorf("unable to start the %s service: %w", name, err)
	}

	// the agent reports Running once it has loaded its config, or stops if it could not
	status, err := waitForWindowsService(s, agentServiceWaitHint, func(state svc.State) bool {
		return state != svc.StartPending
	})
	if err != nil {
		return err
	}

	if status.State != svc.Running {
		return fmt.Errorf("the %s service stopped while starting (exit code %d). Check %s and the Application log in Event Viewer", name, status.ServiceSpecificExitCode, agentServiceLogFile(name))
	}

	log.Info().Msgf("Started the %s service", name)
	return nil
}

func stopAgentService(name string, s *mgr.Service) error {
	if err := stopWindowsService(s); err != nil {
		return err
	}

	log.Info().Msgf("Stopped the %s service", name)
	return nil
}

// openAgentWindowsService opens an installed agent service, refusing services that
// 'infisical agent service install' did not create.
func openAgentWindowsService(name string) (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to connect to the Service Control Manager: %w", err)
	}

	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, nil, fmt.Errorf("no agent service named %s is installed", name)
		}
		return nil, nil, fmt.Errorf("unable to open the %s service: %w", name, err)
	}

	config, err := s.Config()
	if err != nil {
		s.Close()
		m.Disconnect()
		return nil, nil, fmt.Errorf("unable to read the %s service's configuration: %w", name, err)
	}

	if !strings.Contains(config.Description, agentServiceMarker) {
		s.Close()
		m.Disconnect()
		return nil, nil, fmt.Errorf("the %s service was not installed by 'infisical agent service install', refusing to manage it", name)
	}

	return m, s, nil
}

// stopWindowsService asks the service to stop and waits for it to exit. The agent can take up to five
// minutes when it revokes its credentials on shutdown.
func stopWindowsService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("unable to query the service: %w", err)
	}

	if status.State == svc.Stopped {
		return nil
	}

	if status.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("unable to stop the service: %w", err)
		}
	}

	_, err = waitForWindowsService(s, 5*time.Minute+agentServiceWaitHint, func(state svc.State) bool {
		return state == svc.Stopped
	})
	return err
}

// waitForWindowsService polls the service until done accepts its state or the timeout passes.
func waitForWindowsService(s *mgr.Service, timeout time.Duration, done func(svc.State) bool) (svc.Status, error) {
	deadline := time.Now().Add(timeout)
	for {
		status, err := s.Query()
		if err != nil {
			return status, fmt.Errorf("unable to query the service: %w", err)
		}

		if done(status.State) {
			return status, nil
		}

		if time.Now().After(deadline) {
			return status, fmt.Errorf("timed out after %s waiting for the service", timeout)
		}

		time.Sleep(250 * time.Millisecond)
	}
}

// runAgentAsWindowsService runs the agent under the Service Control Manager when the SCM started this
// process. It reports false when the agent was started any other way, such as from a terminal.
func runAgentAsWindowsService(configPath string) (bool, int) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, 0
	}

	service := &agentWindowsService{configPath: configPath}

	// the name is ignored for services that run in their own process; Execute learns the real one
	if err := svc.Run(defaultAgentServiceName, service); err != nil {
		setAgentServiceLogOutput(defaultAgentServiceName)
		log.Error().Msgf("unable to run as a Windows service: %v", err)
		return true, 1
	}

	return true, service.exitCode
}

// agentWindowsService implements the SCM protocol: it reports the agent's state to the SCM and turns
// the SCM's stop and shutdown requests into a graceful agent shutdown.
type agentWindowsService struct {
	configPath string
	exitCode   int
}

func (s *agentWindowsService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: uint32(agentServiceWaitHint.Milliseconds())}

	// a service has no console, so logs go to the log file, with errors copied into the Event Log
	// under the name the service was installed as (args[0])
	elog, elogErr := eventlog.Open(args[0])
	if elogErr == nil {
		defer elog.Close()
		setAgentServiceLogOutput(args[0], eventLogWriter{elog: elog})
	} else {
		setAgentServiceLogOutput(args[0])
		log.Warn().Msgf("unable to open the Windows Event Log, errors are only written to the log file: %v", elogErr)
	}

	configData, err := readAgentServiceConfig(s.configPath)
	if err != nil {
		log.Error().Msg(err.Error())
		s.exitCode = 1
		return true, 1
	}

	// the SCM starts services in C:\Windows\System32, so resolve relative config paths from the config's directory
	if filepath.IsAbs(s.configPath) {
		if err := os.Chdir(filepath.Dir(s.configPath)); err != nil {
			log.Error().Msgf("unable to change to the config directory: %v", err)
		}
	}

	stop := make(chan struct{})
	ready := make(chan struct{}, 1)
	exited := make(chan int, 1)
	go func() {
		exited <- runAgent(s.configPath, configData, stop, func() { ready <- struct{}{} })
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	stopping := false
	var checkpoint uint32
	reportStopPending := func() {
		checkpoint++
		status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: uint32(agentServiceWaitHint.Milliseconds())}
	}

	for {
		select {
		case <-ready:
			status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			if elog != nil {
				_ = elog.Info(agentEventLogID, fmt.Sprintf("Infisical Agent started with config %s", s.configPath))
			}

		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				if !stopping {
					stopping = true
					log.Info().Msg("the Service Control Manager asked the agent to stop")
					close(stop)
				}
				reportStopPending()
			}

		case <-ticker.C:
			// keep the SCM from treating a slow shutdown, such as revoking credentials, as a hung service
			if stopping {
				reportStopPending()
			}

		case code := <-exited:
			if elog != nil {
				_ = elog.Info(agentEventLogID, "Infisical Agent stopped")
			}

			// a requested stop is never reported as a failure: a non-zero exit code would make the
			// recovery actions restart the service the user just stopped
			if stopping {
				return false, 0
			}

			// the SCM did not ask the agent to stop, so report a failure even for exit code 0 (what the agent
			// returns for a config it cannot load), letting the recovery actions retry, e.g. once a missing config appears
			if code == 0 {
				code = 1
			}
			log.Error().Msgf("the agent exited with code %d", code)
			s.exitCode = code
			return true, uint32(code)
		}
	}
}

// eventLogWriter copies error logs into the Windows Event Log, where Windows monitoring tools look for
// service failures. Everything else stays in the log file.
type eventLogWriter struct {
	elog *eventlog.Log
}

func (w eventLogWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w eventLogWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	if level < zerolog.ErrorLevel || level > zerolog.PanicLevel {
		return len(p), nil
	}

	// the Event Log records its own time and level
	var msg bytes.Buffer
	formatter := zerolog.ConsoleWriter{
		Out:          &msg,
		NoColor:      true,
		PartsExclude: []string{zerolog.TimestampFieldName, zerolog.LevelFieldName},
	}
	if _, err := formatter.Write(p); err == nil {
		// failing to reach the Event Log must not stop the agent logging to its file
		_ = w.elog.Error(agentEventLogID, strings.TrimSpace(msg.String()))
	}

	return len(p), nil
}

// MultiLevelWriter only passes the level to writers that implement zerolog.LevelWriter
var _ zerolog.LevelWriter = eventLogWriter{}

func init() {
	agentServiceInstallCmd.Flags().String("config", "agent-config.yaml", "The path to the agent config yaml file the service runs with")

	agentServiceCmd.AddCommand(agentServiceInstallCmd)
	agentServiceCmd.AddCommand(newAgentServiceActionCmd("uninstall", "Stop and remove the agent service (requires Administrator)", uninstallAgentService))
	agentServiceCmd.AddCommand(newAgentServiceActionCmd("start", "Start the agent service (requires Administrator)", startAgentService))
	agentServiceCmd.AddCommand(newAgentServiceActionCmd("stop", "Stop the agent service (requires Administrator)", stopAgentService))

	agentCmd.AddCommand(agentServiceCmd)
}
