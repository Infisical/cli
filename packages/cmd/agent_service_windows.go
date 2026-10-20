//go:build windows

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/agent"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"gopkg.in/natefinch/lumberjack.v2"
)

// the agent writes every Event Log entry under one id; the message carries the detail
const agentEventLogID = 1

// how long the SCM should wait between status updates while the agent starts or stops
const agentServiceWaitHint = 30 * time.Second

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

// checkOwnedByAdministrators fails unless path itself, not what a link there points to, is owned by Administrators
// or SYSTEM. It is only needed for paths install did not create: one install creates is restricted right away.
func checkOwnedByAdministrators(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// FILE_FLAG_OPEN_REPARSE_POINT opens a junction or symbolic link itself; FILE_FLAG_BACKUP_SEMANTICS opens folders
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fmt.Errorf("unable to open %s: %w", path, err)
	}
	defer windows.CloseHandle(handle)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("unable to read %s: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a link to another location, so a standard user may have created it to redirect the agent's logs. Check it, delete it and install again", path)
	}

	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("unable to read the owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("unable to read the owner of %s: %w", path, err)
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("%s is owned by %s rather than Administrators, so a standard user may have created it to read or redirect the agent's logs. Check it, delete it and install again", path, owner)
	}
	return nil
}

// agentServiceDir holds a service's own copies of infisical.exe and of its config
func agentServiceDir(name string) string {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	return filepath.Join(programFiles, "Infisical", "Agent", name)
}

// agentServiceConfigCopy returns the copy of its config a service runs.
func agentServiceConfigCopy(name string) string {
	return filepath.Join(agentServiceDir(name), "service-config.yaml")
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
	ConfigData []byte // the config, as checked; the service runs a copy of it
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

	configData, _, err := readAgentServiceConfig(configPath)
	if err != nil {
		return agentServiceOptions{}, err
	}

	executable, err := os.Executable()
	if err != nil {
		return agentServiceOptions{}, fmt.Errorf("unable to locate the infisical binary: %w", err)
	}

	return agentServiceOptions{Name: name, Executable: executable, ConfigPath: configPath, ConfigData: configData}, nil
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

func checkAgentServiceSupport() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("managing the agent service requires Administrator rights, re-run the command from an elevated prompt (Run as administrator)")
	}
	return nil
}

func installAgentService(name string, configPath string) error {
	opts, err := newAgentServiceOptions(name, configPath)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("unable to connect to the Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(opts.Name); err == nil {
		existing.Close()
		return fmt.Errorf("a service named %s already exists. To replace it, first run: infisical agent service uninstall %s", opts.Name, opts.Name)
	}

	// logs can hold secret values at debug level. Standard users may create folders in %ProgramData%, so the folders
	// that hold the logs, and a log file that already exists, must not be ones a standard user created to read the
	// logs, swap the folder or point it elsewhere
	logFile := agentServiceLogFile(opts.Name)
	for _, dir := range []string{filepath.Dir(filepath.Dir(logFile)), filepath.Dir(logFile)} {
		if err := os.Mkdir(dir, 0o755); os.IsExist(err) {
			if err := checkOwnedByAdministrators(dir); err != nil {
				return err
			}
		} else if err != nil {
			return fmt.Errorf("unable to create %s: %w", dir, err)
		}
		if err := restrictToAdministrators(dir); err != nil {
			return fmt.Errorf("unable to restrict access to %s to Administrators: %w", dir, err)
		}
	}
	if FileExists(logFile) {
		if err := checkOwnedByAdministrators(logFile); err != nil {
			return err
		}
		if err := restrictToAdministrators(logFile); err != nil {
			return fmt.Errorf("unable to restrict access to %s to Administrators: %w", logFile, err)
		}
	}

	executable, err := copyAgentServiceExecutable(opts.Name, opts.Executable)
	if err != nil {
		return fmt.Errorf("unable to copy infisical.exe into %s: %w", agentServiceDir(opts.Name), err)
	}

	// the config decides what the service runs (execute commands) and writes, so the service runs its own copy, in its
	// folder: a standard user who can edit the original, or still has it open from before, cannot change the copy
	configCopy := agentServiceConfigCopy(opts.Name)
	if err := os.WriteFile(configCopy, opts.ConfigData, 0o600); err != nil {
		return fmt.Errorf("unable to copy the config into %s: %w", agentServiceDir(opts.Name), err)
	}

	s, err := m.CreateService(opts.Name, executable, mgr.Config{
		DisplayName: fmt.Sprintf("Infisical Agent (%s)", opts.Name),
		Description: "Authenticates with Infisical and keeps secrets, tokens and certificates on this machine up to date. " + agentServiceMarker + ".",
		StartType:   mgr.StartAutomatic,
	}, "agent", "--config", configCopy)
	if err != nil {
		return fmt.Errorf("unable to create the %s service: %w", opts.Name, err)
	}
	defer s.Close()

	// relative paths in the config resolve from the original config's directory, which the service finds in its environment
	if err := setAgentServiceEnvironment(opts.Name, agent.WorkingDirEnvName+"="+filepath.Dir(opts.ConfigPath)); err != nil {
		return deleteIncompleteService(s, fmt.Errorf("unable to set the service's environment: %w", err))
	}

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
	log.Info().Msgf("The service runs its own copies of infisical.exe and the config from %s, which only Administrators can change. To change its config, edit %s and restart the service, or uninstall and install it again (also how to upgrade it)", filepath.Dir(executable), configCopy)
	log.Info().Msg("Keep the templates and credential files the config points to in folders only Administrators can change too")
	log.Info().Msgf("Start it now with: infisical agent service start %s", opts.Name)
	return nil
}

// setAgentServiceEnvironment sets the environment the SCM starts the service with.
func setAgentServiceEnvironment(name string, variables ...string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringsValue("Environment", variables)
}

func deleteIncompleteService(s *mgr.Service, cause error) error {
	if err := s.Delete(); err != nil {
		return fmt.Errorf("%w (removing the incomplete service also failed: %v)", cause, err)
	}
	return cause
}

// uninstall, start and stop each open the agent's service once for their action
var (
	uninstallAgentService = withAgentWindowsService(uninstallOpenedAgentService)
	startAgentService     = withAgentWindowsService(startOpenedAgentService)
	stopAgentService      = withAgentWindowsService(stopOpenedAgentService)
)

// withAgentWindowsService opens an agent service that 'infisical agent service install' created, runs action on
// it and closes it.
func withAgentWindowsService(action func(name string, s *mgr.Service) error) func(name string) error {
	return func(name string) error {
		m, s, err := openAgentWindowsService(name)
		if err != nil {
			return err
		}
		defer m.Disconnect()
		defer s.Close()

		return action(name, s)
	}
}

func uninstallOpenedAgentService(name string, s *mgr.Service) error {
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

	// only the service's own copies of infisical.exe and the config: the folder may also hold templates or credentials,
	// so it is removed only once empty
	for _, copied := range []string{filepath.Join(agentServiceDir(name), "infisical.exe"), agentServiceConfigCopy(name)} {
		if err := os.Remove(copied); err != nil && !os.IsNotExist(err) {
			log.Warn().Msgf("unable to remove %s: %v", copied, err)
		}
	}
	_ = os.Remove(agentServiceDir(name))

	log.Info().Msgf("Uninstalled the %s service", name)
	return nil
}

func startOpenedAgentService(name string, s *mgr.Service) error {
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

func stopOpenedAgentService(name string, s *mgr.Service) error {
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

	// the SCM starts services in C:\Windows\System32, and the service runs a copy of its config, so install stores
	// the directory relative paths resolve from: the original config's
	workingDir := os.Getenv(agent.WorkingDirEnvName)
	if workingDir == "" {
		workingDir = filepath.Dir(s.configPath)
	}
	if err := os.Chdir(workingDir); err != nil {
		log.Error().Msgf("unable to change to the config directory: %v", err)
	}

	// the service runs the config it was installed with, which a machine-wide INFISICAL_AGENT_CONFIG_BASE64 would replace
	os.Unsetenv("INFISICAL_AGENT_CONFIG_BASE64")

	stop := make(chan struct{})
	ready := make(chan struct{}, 1)
	exited := make(chan int, 1)
	go func() {
		exited <- runAgent(s.configPath, stop, func() { ready <- struct{}{} })
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
