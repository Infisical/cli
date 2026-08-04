package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/tools/clientcmd"
	k8sapi "k8s.io/client-go/tools/clientcmd/api"
)

// maxKubeContextLen keeps a context name to a length kubectl and the instruction document can carry
// comfortably.
const maxKubeContextLen = 200

// Options configures a single `pam agentic access` run.
type Options struct {
	// Accounts narrows the run to these paths. Empty means every account the caller can launch.
	Accounts []string
	Duration time.Duration
	Reason   string

	Argv          []string
	AgentOverride string
	LogFile       string
	AccessToken   string
}

// Run binds a proxy per account and launches the agent. It returns the child's exit code.
func Run(opts Options) (int, error) {
	httpClient := resty.New()
	httpClient.SetAuthToken(opts.AccessToken)
	httpClient.SetHeader("User-Agent", api.USER_AGENT)

	// Work out what to bind and check it could actually launch, without creating any sessions.
	resolved, skipped, err := ResolveAccounts(httpClient, opts)
	if err != nil {
		return 1, err
	}

	session := &runSession{httpClient: httpClient, skipped: skipped}
	defer session.cleanup()

	if err := session.startProxies(resolved); err != nil {
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

func (s *runSession) startProxies(resolved []ResolvedAccount) error {
	for _, account := range resolved {
		provider := NewLazySessionProvider(s.httpClient, account.Path, account.Reason, account.Duration)
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

func (s *runSession) childEnv(document string) ([]string, error) {
	contextPath, err := s.writeContextFile(document)
	if err != nil {
		return nil, err
	}

	env := append(os.Environ(), s.extraEnv...)
	env = append(env, fmt.Sprintf("INFISICAL_PAM_CONTEXT_FILE=%s", contextPath))
	return env, nil
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

	command := exec.Command(delivery.Args[0], delivery.Args[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = env

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
		util.PrintfStderr("    127.0.0.1:%-6d %s (%s)\n", account.Port, account.Path, account.TypeLabel)
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

// writeKubeconfig builds a kubeconfig covering every kubernetes account, or returns "" if none.
//
// It also records each cluster's context name on the account, and which one ended up as the current
// context, so the instructions can tell the agent when a --context flag is needed.
func (s *runSession) writeKubeconfig() (string, error) {
	config := k8sapi.NewConfig()
	taken := make(map[string]bool)

	for i, account := range s.liveAccounts {
		if account.Type != "kubernetes" {
			continue
		}

		name := kubeContextName(account.Path, taken)

		config.Clusters[name] = &k8sapi.Cluster{Server: fmt.Sprintf("http://127.0.0.1:%d", account.Port)}
		config.AuthInfos[name] = &k8sapi.AuthInfo{}
		config.Contexts[name] = &k8sapi.Context{Cluster: name, AuthInfo: name}

		s.liveAccounts[i].KubeContext = name

		if config.CurrentContext == "" {
			config.CurrentContext = name
			s.liveAccounts[i].IsCurrentKubeContext = true
		}
	}

	if config.CurrentContext == "" {
		return "", nil
	}

	// Serialized by client-go rather than assembled as text, so nothing that arrives in an account
	// path can turn into kubeconfig structure. A newline in the wrong place could otherwise add an
	// exec credential plugin, which kubectl runs as a command.
	contents, err := clientcmd.Write(*config)
	if err != nil {
		return "", fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	path := filepath.Join(s.tempDir, "kubeconfig")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		return "", fmt.Errorf("failed to write kubeconfig: %w", err)
	}
	return path, nil
}

// kubeContextName turns an account path into a context name.
//
// The name reaches kubectl and the instruction document, so it is reduced to letters, digits, dots,
// dashes and underscores. Names also have to stay distinct: contexts live in a map, so a repeat would
// overwrite an entry and leave one cluster answering on another one's proxy.
func kubeContextName(path string, taken map[string]bool) string {
	var out strings.Builder
	out.WriteString("infisical-pam-")

	dashed := false
	for _, r := range path {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			out.WriteRune(r)
			dashed = false
		case !dashed:
			out.WriteRune('-')
			dashed = true
		}
	}

	name := strings.TrimRight(out.String(), "-")
	if len(name) > maxKubeContextLen {
		name = strings.TrimRight(name[:maxKubeContextLen], "-")
	}

	unique := name
	for attempt := 2; taken[unique]; attempt++ {
		unique = fmt.Sprintf("%s-%d", name, attempt)
	}
	taken[unique] = true
	return unique
}
