package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Options configures a single `pam agentic access` run.
type Options struct {
	// Accounts narrows the run to these paths. Empty means every account the caller can launch.
	Accounts []string
	Duration time.Duration
	Reason   string

	// RequestApproval allows raising an access request the first time the agent touches an account
	// that is gated behind approval. Off means such an account simply reports the gate and stays
	// unusable for the run.
	RequestApproval bool

	// NoSandbox runs the agent uncontained, giving up the credential boundary in sandboxChild. It is the
	// only way to run on a host with no OS sandbox, since that case fails rather than downgrading, and
	// the escape hatch for an agent that needs a denied path.
	NoSandbox bool

	Argv          []string
	AgentOverride string
	LogFile       string

	// AccessToken returns the token to authenticate PAM API calls with. It is a function rather than a
	// string because an agent session outlives a single token: when a machine identity authenticated
	// itself, the SDK renews in the background and this returns the current value.
	AccessToken func() string
}

// Run binds a proxy per account and launches the agent. It returns the child's exit code.
func Run(opts Options) (int, error) {
	httpClient := resty.New()
	httpClient.SetHeader("User-Agent", api.USER_AGENT)

	// Read the token per request rather than fixing it once. Sessions are created lazily and ended at
	// teardown, so calls happen throughout a run that can outlast the token it started with.
	httpClient.OnBeforeRequest(func(_ *resty.Client, request *resty.Request) error {
		request.SetAuthToken(opts.AccessToken())
		return nil
	})

	// Work out what to bind and check it could actually launch, without creating any sessions.
	resolved, skipped, err := ResolveAccounts(httpClient, opts)
	if err != nil {
		return 1, err
	}

	session := &runSession{httpClient: httpClient, skipped: skipped}
	defer session.cleanup()

	if err := session.startProxies(resolved, opts.RequestApproval); err != nil {
		return 1, err
	}

	document := RenderInstructions(session.liveAccounts)

	return session.runChild(document, opts)
}

// runSession owns everything created during a run so teardown has a single place to look.
type runSession struct {
	httpClient   *resty.Client
	proxies      []*AgentProxy
	liveAccounts []LiveAccount
	skipped      []SkippedAccount
	tempDir      string
	extraEnv     []string
	cleanups     []func()
}

func (s *runSession) startProxies(resolved []ResolvedAccount, requestApproval bool) error {
	for _, account := range resolved {
		provider := NewLazySessionProvider(s.httpClient, account.Path, account.Reason, account.Duration, requestApproval)
		proxy := NewAgentProxy(s.httpClient, account.Path, account.AccountType, provider)

		// Port 0 asks the OS for a free one. The listener then holds it for the whole run, so the
		// port an account is announced on is the port it keeps, and nothing else can take it.
		if err := proxy.Start(0); err != nil {
			return fmt.Errorf("could not bind a port for %s: %w", account.Path, err)
		}

		s.proxies = append(s.proxies, proxy)
		go proxy.Run()

		connectionString, example := connectionFor(account.AccountType, proxy.Port())
		s.liveAccounts = append(s.liveAccounts, LiveAccount{
			Path:             account.Path,
			Type:             account.AccountType,
			TypeLabel:        account.TypeLabel,
			Host:             "127.0.0.1",
			Port:             proxy.Port(),
			ConnectionString: connectionString,
			Example:          example,
			AwaitingApproval: account.AwaitingApproval(),
			RequiresApproval: account.RequiresApproval,
		})
	}

	return s.prepareEnvironment()
}

// prepareEnvironment writes the context file and assembles the variables the child inherits.
func (s *runSession) prepareEnvironment() error {
	tempDir, err := os.MkdirTemp("", "infisical-pam-agentic-")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	s.tempDir = tempDir
	s.cleanups = append(s.cleanups, func() { os.RemoveAll(tempDir) })

	// Kubernetes clients read a kubeconfig, so one is written for this run and scoped to the child
	// process, leaving the user's own kubeconfig and current context alone.
	kubeconfigPath, err := s.writeKubeconfig()
	if err != nil {
		return err
	}
	if kubeconfigPath != "" {
		s.extraEnv = append(s.extraEnv, fmt.Sprintf("KUBECONFIG=%s", kubeconfigPath))
	}

	return nil
}

// writeContextFile persists the instruction document so any agent can read it by path.
func (s *runSession) writeContextFile(document string) (string, error) {
	path := filepath.Join(s.tempDir, "infisical-pam-context.md")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		return "", fmt.Errorf("failed to write context file: %w", err)
	}
	return path, nil
}

// infisicalAuthEnvKeys are the variables the CLI's own auth resolution reads. The agent reaches its
// accounts over loopback and never needs an Infisical credential, so none of these are handed down:
// one that was would let it call the API directly and open sessions outside the accounts, duration and
// approval gates this run was launched with.
//
// This is hygiene, not a boundary. A child running as the same user can still read the parent's argv,
// so it is the sandbox below, not this list, that contains a deliberately hostile agent.
var infisicalAuthEnvKeys = []string{
	util.INFISICAL_TOKEN_NAME,
	util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME,
	util.INFISICAL_GATEWAY_TOKEN_NAME_LEGACY, // bare "TOKEN", still read by util.GetInfisicalToken
	util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME,
	util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME,
	util.INFISICAL_JWT_NAME,
	util.INFISICAL_OIDC_AUTH_JWT_NAME,
	util.INFISICAL_LDAP_USERNAME,
	util.INFISICAL_LDAP_PASSWORD,
	util.INFISICAL_KUBERNETES_SERVICE_ACCOUNT_TOKEN_NAME,
	util.INFISICAL_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH_NAME,
	util.INFISICAL_AUTH_METHOD_NAME,
	util.INFISICAL_MACHINE_IDENTITY_ID_NAME,
	util.INFISICAL_ORGANIZATION_ID,
	util.INFISICAL_VAULT_FILE_PASSPHRASE_ENV_NAME, // unlocks the file-backed keyring
	util.INFISICAL_BOOTSTRAP_EMAIL_NAME,
	util.INFISICAL_BOOTSTRAP_PASSWORD_NAME,
	util.INFISICAL_BOOTSTRAP_ORGANIZATION_NAME,
}

func (s *runSession) childEnv(document string) ([]string, error) {
	contextPath, err := s.writeContextFile(document)
	if err != nil {
		return nil, err
	}

	stripped := make(map[string]bool, len(infisicalAuthEnvKeys))
	for _, key := range infisicalAuthEnvKeys {
		stripped[key] = true
	}

	var env []string
	for _, entry := range os.Environ() {
		if name, _, found := strings.Cut(entry, "="); found && stripped[name] {
			continue
		}
		env = append(env, entry)
	}

	env = append(env, s.extraEnv...)
	env = append(env, fmt.Sprintf("INFISICAL_PAM_CONTEXT_FILE=%s", contextPath))
	return env, nil
}

// sandboxChild puts the agent behind the OS sandbox (macOS Seatbelt, Linux bubblewrap).
//
// One of the agent proxy's controls is deliberately not used: the network fence. PAM's proxies are
// per-account TCP listeners rather than a forward proxy, so there is no route out to confine the agent
// to, and it still needs its own egress to reach the API behind it.
//
// What is kept, and is the point: the agent cannot authenticate as the user who launched the run, so
// it cannot step outside its brokered sessions. The keyring stays unreachable (the macOS keychain
// services are denied by default) and so does everything the CLI stores, per pamDenyPaths. Writes are
// confined to the working directory, this run's temp dir and the agent's own state dirs.
func (s *runSession) sandboxChild(argv, env []string, noSandbox bool) (*exec.Cmd, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve the working directory: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve the home directory: %w", err)
	}

	spec := sandbox.Spec{
		Enabled:     !noSandbox,
		Cwd:         cwd,
		TempDir:     s.tempDir,
		WritePaths:  agentStateWritePaths(home),
		DenyPaths:   pamDenyPaths(home, hostRuntimeDir()),
		DenySockets: pamDenySockets(home),
		Env:         env,
		NetMode:     sandbox.SharedNet,
	}

	backend := sandbox.NewBackend(spec)
	pre, err := backend.Preflight(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to check sandbox support on this host: %w", err)
	}

	// Fail closed. A host that cannot start a sandbox must not silently get an uncontained agent that
	// can read the caller's Infisical credentials: running without the boundary has to be something the
	// operator chose with --no-sandbox, which every Reason here already names. With that flag the
	// backend is the passthrough one, whose Preflight always reports support, so this never blocks an
	// explicit opt-out.
	if !pre.Supported {
		return nil, fmt.Errorf("%s", pre.Reason)
	}

	// Explicitly uncontained, so say so once: the deny set and the keyring boundary are both gone.
	if !spec.Enabled {
		util.PrintfStderr("\n  Warning: --no-sandbox, so the agent is running uncontained.\n")
		util.PrintfStderr("  It can read your Infisical login and other credential files on this host.\n")
	}

	return backend.Wrap(spec, argv)
}

// pamDenySockets lists container-runtime control sockets. A daemon socket is root-equivalent: an agent
// that can reach one can start a container that bind-mounts the home directory, read straight through
// every mask in pamDenyPaths, and then authenticate as the caller to open PAM sessions outside this
// run's accounts, duration and approval gates.
//
// These are kept apart from pamDenyPaths because a path mask does not cover a socket. Connecting to one
// is a network operation, so it survives a file deny and needs the socket-specific control instead.
//
// Symlinked sockets are listed by their target as well, since seatbelt matches the resolved path and
// Docker Desktop points /var/run/docker.sock at the one under ~/.docker.
func pamDenySockets(home string) []string {
	candidates := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/podman/podman.sock",
		"/run/podman/podman.sock",
		"/var/run/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
		"/var/run/buildkit/buildkitd.sock",
	}
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".docker", "run", "docker.sock"),           // Docker Desktop
			filepath.Join(home, ".rd", "docker.sock"),                      // Rancher Desktop
			filepath.Join(home, ".colima", "default", "docker.sock"),       // Colima
			filepath.Join(home, ".orbstack", "run", "docker.sock"),         // OrbStack
			filepath.Join(home, ".lima", "default", "sock", "docker.sock"), // Lima
			filepath.Join(home, ".local", "share", "containers", "podman", "machine", "podman.sock"),
		)
	}

	sockets := make([]string, 0, len(candidates))
	for _, path := range candidates {
		sockets = append(sockets, path)
		if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
			sockets = append(sockets, resolved)
		}
	}
	return sockets
}

// pamDenyPaths is deliberately narrower than sandbox.DefaultDenyPaths. The agent proxy withholds every
// credential it can find, because its promise is that the agent never holds one. PAM's promise is
// narrower: privileged account access is brokered, session-bound and audited. The agent is a working
// coding agent in the caller's own repo, so denying ~/.aws, ~/.ssh or ~/.kube would break ordinary work
// (git over SSH, the cloud CLIs) without protecting anything PAM is responsible for.
//
// Two things are denied. Everything the Infisical CLI authenticates with, since that is what would let
// the agent call the API directly and open sessions outside this run's accounts, duration and approval
// gates. And, on Linux, the per-user runtime directory, which is not a credential at all: it carries
// the session bus, where systemd --user StartTransientUnit starts a process outside the sandbox, and
// the secret-service socket the "auto" vault backend keeps the login in. Leaving it open would make the
// first denial unenforceable, so it stays shut even though the rest has been opened up.
func pamDenyPaths(home, runtimeDir string) []string {
	if home == "" {
		return nil
	}
	paths := []string{
		filepath.Join(home, ".infisical"),           // config file: logged-in email and domain
		filepath.Join(home, "infisical-keyring"),    // file-vault backend store (JWT + backup key)
		filepath.Join(home, ".config", "infisical"), // XDG config location
	}
	if runtimeDir != "" {
		paths = append(paths, runtimeDir)
	}
	return paths
}

// agentStateWritePaths returns the state directories the supported agents need to write: sessions,
// transcripts, history and config. Without them an agent starts but cannot record anything, which
// surfaces as permission-denied transcript writes rather than as a sandbox error.
//
// Only paths that already exist are returned, since bwrap --bind fails on a missing source.
func agentStateWritePaths(home string) []string {
	if home == "" {
		return nil
	}
	candidates := []string{
		filepath.Join(home, ".claude"),      // Claude Code state (sessions, history, cache)
		filepath.Join(home, ".claude.json"), // Claude Code top-level config
		filepath.Join(home, ".codex"),       // Codex state
		filepath.Join(home, ".gemini"),      // Gemini CLI state
	}

	var paths []string
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}

// hostRuntimeDir is the per-user runtime directory holding host IPC sockets, which DefaultDenyPaths
// keeps out of reach. Linux only, since those sockets are not namespaced there; empty elsewhere.
func hostRuntimeDir() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	return fmt.Sprintf("/run/user/%d", os.Getuid())
}

func (s *runSession) runChild(document string, opts Options) (int, error) {
	adapter := SelectAdapter(opts.Argv, opts.AgentOverride)

	delivery, err := adapter.Apply(document, opts.Argv)
	if err != nil {
		return 1, err
	}
	s.cleanups = append(s.cleanups, delivery.Cleanup)

	env, err := s.childEnv(document)
	if err != nil {
		return 1, err
	}

	logFile, err := s.redirectLogs(opts.LogFile)
	if err != nil {
		return 1, err
	}

	s.printBanner(adapter, delivery, logFile)

	// Wrap returns the command ready to start with stdio inherited; PAM keeps its own signal handling
	// below rather than sandbox.ForwardTerminationSignals, which forwards SIGINT.
	command, err := s.sandboxChild(delivery.Args, env, opts.NoSandbox)
	if err != nil {
		return 1, err
	}

	if err := command.Start(); err != nil {
		return 1, fmt.Errorf("failed to start %s: %w", delivery.Args[0], err)
	}

	// The child owns the terminal from here.
	//
	// Ctrl+C is delivered by the terminal to the whole foreground process group, so the child
	// already receives it. We must catch it too, otherwise the default handler would kill us
	// before cleanup, but we deliberately do NOT forward it: a second SIGINT would make one
	// keypress look like two to agents that treat the first as "interrupt" and the second as
	// "quit". SIGTERM is different, it is addressed to this process alone, so it is forwarded.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-signals:
				if sig == syscall.SIGTERM && command.Process != nil {
					_ = command.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	waitErr := command.Wait()
	close(done)

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if waitErr != nil {
		return 1, fmt.Errorf("%s failed: %w", delivery.Args[0], waitErr)
	}
	return 0, nil
}

// redirectLogs sends proxy logging to a file so it cannot corrupt the agent's terminal UI.
func (s *runSession) redirectLogs(path string) (string, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to resolve home directory: %w", err)
		}
		dir := filepath.Join(home, ".infisical", "pam-agentic")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("failed to create log directory: %w", err)
		}
		path = filepath.Join(dir, "access.log")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to open log file %s: %w", path, err)
	}
	s.cleanups = append(s.cleanups, func() { file.Close() })

	log.Logger = zerolog.New(file).With().Timestamp().Logger()
	return path, nil
}

func (s *runSession) printBanner(adapter Adapter, delivery Delivery, logFile string) {
	util.PrintfStderr("\n")
	util.PrintfStderr("  Infisical PAM proxies ready for %s\n", adapter.Name)
	util.PrintfStderr("\n")
	for _, account := range s.liveAccounts {
		// An account still gated behind approval has a port but no session yet, so say so here rather
		// than letting it look identical to one that is ready.
		status := ""
		if account.AwaitingApproval {
			status = "  [awaiting approval]"
		}
		util.PrintfStderr("    127.0.0.1:%-6d %s (%s)%s\n", account.Port, account.Path, account.TypeLabel, status)
	}
	util.PrintfStderr("\n")

	// Say what was left out and why, so an account missing from the list above is explained.
	if len(s.skipped) > 0 {
		util.PrintfStderr("  Not started:\n")
		for _, account := range s.skipped {
			util.PrintfStderr("    %s: %s\n", account.Path, account.Reason)
		}
		util.PrintfStderr("\n")
	}
	if delivery.Summary != "" {
		util.PrintfStderr("  Instructions %s\n", delivery.Summary)
	}
	util.PrintfStderr("  Proxy logs: %s\n", logFile)
	util.PrintfStderr("\n")
}

// cleanup tears everything down: context files, injected blocks, proxies and any live sessions.
func (s *runSession) cleanup() {
	var failures []string

	// Shut the proxies down concurrently. Each one waits for its connections to finish and then for
	// its session to be ended, and that wait needs to overlap: teardown that looks stuck invites a
	// second Ctrl+C, which would kill the process with sessions still live.
	var wait sync.WaitGroup
	for _, proxy := range s.proxies {
		wait.Add(1)
		go func(proxy *AgentProxy) {
			defer wait.Done()
			proxy.Shutdown()
		}(proxy)
	}
	wait.Wait()

	for _, proxy := range s.proxies {
		if err := proxy.LastError(); err != nil {
			failures = append(failures, err.Error())
		}
	}

	// Run cleanups in reverse so files are restored before their directories disappear.
	for i := len(s.cleanups) - 1; i >= 0; i-- {
		s.cleanups[i]()
	}

	// Connection failures were logged to a file the user wasn't watching, so surface them now.
	if len(failures) > 0 {
		util.PrintfStderr("\n  Some PAM connections failed during this run:\n")
		for _, failure := range failures {
			util.PrintfStderr("    - %s\n", failure)
		}
		util.PrintfStderr("\n")
	}
}
