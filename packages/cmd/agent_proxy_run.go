package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var agentProxyRunCmd = &cobra.Command{
	Use:                   "run [flags] -- [agent start command]",
	Short:                 "Run an untrusted agent locally with secrets brokered on the wire and an OS sandbox as the trust boundary",
	Example:               "infisical secrets agent-proxy run --env=prod --path=/myapp -- claude",
	DisableFlagsInUseLine: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("provide the agent command to run after '--', e.g. -- claude")
		}
		return nil
	},
	Run: runAgentProxyRun,
}

// secretShapedEnvSubstrings: env vars whose name contains any of these are scrubbed from the child
// (coarse on purpose; --pass-env re-admits a specific one).
var secretShapedEnvSubstrings = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY", "PRIVATE_KEY", "ACCESS_KEY",
}

func runAgentProxyRun(cmd *cobra.Command, args []string) {
	if cmd.Flags().Changed("proxy") {
		util.HandleError(fmt.Errorf("--proxy is not valid for 'run' (it starts its own ephemeral proxy); use 'agent-proxy connect --proxy=host:port' for a remote proxy"))
	}

	environment, err := cmd.Flags().GetString("env")
	if err != nil {
		util.HandleError(err, "Unable to parse --env")
	}
	if !cmd.Flags().Changed("env") {
		if envFromWorkspace := util.GetEnvFromWorkspaceFile(); envFromWorkspace != "" {
			environment = envFromWorkspace
		}
	}
	if environment == "" {
		util.HandleError(fmt.Errorf("the --env flag is required"))
	}

	secretPath, err := cmd.Flags().GetString("path")
	if err != nil {
		util.HandleError(err, "Unable to parse --path")
	}

	projectID, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "projectId", []string{util.INFISICAL_PROJECT_ID_NAME}, "")
	if err != nil {
		util.HandleError(err, "Unable to parse --projectId")
	}
	if projectID == "" {
		if workspaceFile, wsErr := util.GetWorkSpaceFromFile(); wsErr == nil {
			projectID = workspaceFile.WorkspaceId
		}
	}
	if projectID == "" {
		util.HandleError(fmt.Errorf("project id is required; pass --projectId, set INFISICAL_PROJECT_ID, or run inside a project with .infisical.json"))
	}

	unmatchedHost, _ := cmd.Flags().GetString("unmatched-host")
	if unmatchedHost != agentproxy.UnmatchedAllow && unmatchedHost != agentproxy.UnmatchedBlock {
		util.HandleError(fmt.Errorf("--unmatched-host must be 'allow' or 'block', got %q", unmatchedHost))
	}
	pollInterval, _ := cmd.Flags().GetInt("poll-interval")

	sandboxEnabled := resolveSandboxEnabled(cmd)

	// The single identity for the run: fetches config and secret values in the parent. The child gets none of it.
	src := resolveDeveloperTokenSource(cmd)

	httpClient := resty.New().SetAuthToken(src.token())
	placeholders := fetchLocalProxiedServiceConfig(httpClient, projectID, environment, secretPath)

	local := &agentproxy.LocalOptions{
		ProjectID:     projectID,
		Environment:   environment,
		SecretPath:    secretPath,
		UserToken:     src.token,
		InfisicalHost: infisicalAPIHost(),
		IdentityID:    src.label,
		IdentityName:  src.label,
	}

	// Per-run 0700 tempdir: only the public CA cert (and the unix socket on the Linux hard fence) hit disk.
	tempDir, err := os.MkdirTemp("", "infisical-agent-proxy-run-")
	if err != nil {
		util.HandleError(err, "Failed to create the per-run temp directory")
	}
	// os.Exit (and util.HandleError) skip deferred funcs, so clean up explicitly at every exit path.
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	fail := func(e error, messages ...string) { cleanup(); util.HandleError(e, messages...) }

	// Unlike `start` (a daemon whose activity log IS its output), `run` wraps an interactive agent that
	// owns the terminal. Route the proxy's per-request activity and poll logs to a file so they don't
	// interleave with the agent's output. --log-file picks a stable path (survives teardown); the
	// default lives in the per-run tempdir and is removed on exit (tail it live to watch brokering).
	// HandleError/PrintWarning write to stderr independently, so errors and one-time notices still show.
	logFile, _ := cmd.Flags().GetString("log-file")
	logPath := logFile
	if logPath == "" {
		logPath = filepath.Join(tempDir, "agent-proxy.log")
	}
	logF, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fail(err, "Failed to open the proxy log file")
	}
	log.Logger = log.Output(GetLoggerConfig(logF, true))

	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	extraRead, _ := cmd.Flags().GetStringArray("allow-read")
	extraWrite, _ := cmd.Flags().GetStringArray("allow-write")
	allowHosts, _ := cmd.Flags().GetStringArray("allow-host")

	// On macOS, persist the local root under ~/.infisical (already sandbox-denied, so the agent can't
	// read the key) and trust it once in the keychain, so native-trust tools (Go CLIs like gh) can be
	// brokered too. Elsewhere the injected CA env var is enough, so we keep an ephemeral in-memory root.
	if runtime.GOOS == "darwin" && home != "" {
		local.CADir = filepath.Join(home, ".infisical", "agent-proxy")
	}

	// Supported agents persist their own state under home; make those dirs writable so interactive
	// sessions can save. It's the agent's own data, not the developer's secrets.
	writePaths := append(defaultAgentStateWritePaths(home), extraWrite...)

	spec := sandbox.SandboxSpec{
		Sandbox:    sandboxEnabled,
		ReadPaths:  extraRead,
		WritePaths: writePaths,
		DenyPaths:  sandbox.DefaultDenyPaths(home),
		Cwd:        cwd,
		TempDir:    tempDir,
		// Linux downgrades to SharedNet via Preflight below; macOS always fences to loopback via SBPL.
		NetMode: sandbox.HardFence,
	}

	// Preflight must run before choosing the listener and building the env (the proxy URL depends on
	// whether the bridge is used).
	backend := sandbox.NewBackend(spec)
	pre, err := backend.Preflight(spec)
	if err != nil {
		fail(err, "Sandbox preflight failed")
	}
	if !pre.Supported {
		fail(fmt.Errorf("%s", pre.Reason))
	}
	if pre.FallbackToSharedNet {
		spec.NetMode = sandbox.SharedNet
		util.PrintWarning(fmt.Sprintf("network hard-fence unavailable (%s); falling back to shared host networking. Your credentials remain protected (env scrub, keyring block, filesystem deny); only the network isolation is reduced.", pre.Reason))
	}

	proxy, err := agentproxy.New(agentproxy.Options{
		UnmatchedHost: unmatchedHost,
		PollInterval:  time.Duration(pollInterval) * time.Second,
		Local:         local,
		AllowedHosts:  allowHosts,
	})
	if err != nil {
		fail(err, "Failed to initialize the ephemeral agent proxy")
	}

	// macOS: trust the persistent root once so native-trust tools (gh) accept the proxy's certs, and
	// allow trustd in the profile for the sandbox. securityd stays blocked, so the token stays
	// unreadable. Trust-install is non-fatal: env-CA tools (Claude Code, Codex, curl) work regardless.
	if local.CADir != "" {
		if sandboxEnabled {
			spec.AllowTrustd = true
		}
		switch installed, terr := ensureCATrusted(agentproxy.LocalCACertPath(local.CADir)); {
		case terr != nil:
			util.PrintWarning(fmt.Sprintf("could not trust the local CA in your keychain (%v); Go-native tools like gh won't be brokered, but Claude Code, Codex, and curl still will", terr))
		case installed:
			util.PrintWarning("added the Infisical agent-proxy local CA to your login keychain (one-time) so native-trust tools can be brokered; it persists for future runs")
		}
	}

	// Hard fence: proxy on a unix socket in the tempdir, reached via the bridge. Otherwise: TCP loopback.
	var listener net.Listener
	var childProxyURL string
	if pre.UsesBridge {
		spec.ProxySocket = filepath.Join(tempDir, "proxy.sock")
		listener, err = net.Listen("unix", spec.ProxySocket)
		if err != nil {
			fail(err, "Failed to bind the ephemeral proxy on its unix socket")
		}
		spec.LoopbackPort = sandbox.BridgeLoopbackPort
		childProxyURL = fmt.Sprintf("http://127.0.0.1:%d", sandbox.BridgeLoopbackPort)
	} else {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fail(err, "Failed to bind the ephemeral proxy on loopback")
		}
		spec.LoopbackPort = listener.Addr().(*net.TCPAddr).Port
		childProxyURL = localProxyURL(listener.Addr().String())
	}

	caPath := filepath.Join(tempDir, "local-ca.pem")
	if err := os.WriteFile(caPath, proxy.LocalRootPEM(), 0o600); err != nil {
		fail(err, "Failed to write the local CA certificate")
	}

	proxyErrCh := make(chan error, 1)
	go func() { proxyErrCh <- proxy.Serve(listener) }()

	spec.Env = buildLocalAgentEnv(cmd, childProxyURL, caPath, placeholders)

	if !sandboxEnabled {
		util.PrintWarning("running WITHOUT the OS sandbox (--no-sandbox): the agent is uncontained and can read your keyring, credential files, and reach the network directly. Secrets are still brokered on the wire, but the sandbox boundary is off.")
	} else {
		fmt.Fprintln(os.Stderr, color.HiBlackString("Local coupled mode: the proxy acts with your own access and the OS sandbox is the boundary that keeps the agent from reading your credentials directly."))
	}
	fmt.Fprintln(os.Stderr, color.HiBlackString("proxy activity log: "+logPath))

	child, err := backend.Wrap(spec, args)
	if err != nil {
		shutdownProxy(proxy)
		fail(err, "Failed to wrap the agent command in the sandbox")
	}

	exitCode := runSandboxedChild(child, proxy, proxyErrCh)
	shutdownProxy(proxy)
	cleanup()
	os.Exit(exitCode)
}

// runSandboxedChild starts the child, forwards signals, and returns its exit code; if the proxy dies
// first it kills the child.
func runSandboxedChild(child *exec.Cmd, proxy *agentproxy.Proxy, proxyErrCh <-chan error) int {
	fmt.Fprintln(os.Stderr, color.GreenString("Starting agent behind the Infisical agent proxy (sandboxed)"))

	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start the agent process: %v\n", err)
		return 1
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh)
	go func() {
		for sig := range sigCh {
			if child.Process != nil {
				_ = child.Process.Signal(sig)
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- child.Wait() }()

	select {
	case err := <-proxyErrCh:
		fmt.Fprintf(os.Stderr, "%s\n", color.RedString("the ephemeral proxy stopped unexpectedly (%v); terminating the agent", err))
		if child.Process != nil {
			_ = child.Process.Kill()
		}
		<-waitCh
		return 1
	case err := <-waitCh:
		signal.Stop(sigCh)
		return exitCodeFromWait(err)
	}
}

func exitCodeFromWait(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			return ws.ExitStatus()
		}
	}
	fmt.Fprintf(os.Stderr, "agent process error: %v\n", err)
	return 1
}

func shutdownProxy(proxy *agentproxy.Proxy) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxy.Shutdown(ctx)
}

// resolveSandboxEnabled reads the toggle from flag or env only, never .infisical.json (a committed
// file must not be able to silently disable the boundary).
func resolveSandboxEnabled(cmd *cobra.Command) bool {
	if cmd.Flags().Changed("sandbox") {
		v, _ := cmd.Flags().GetBool("sandbox")
		return v
	}
	if cmd.Flags().Changed("no-sandbox") {
		v, _ := cmd.Flags().GetBool("no-sandbox")
		return !v
	}
	if v := os.Getenv("INFISICAL_AGENT_PROXY_SANDBOX"); v != "" {
		return !(v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off"))
	}
	return true
}

// tokenSource is the parent-held identity for a run. token() is read per request so a future
// refresher can rotate it; label names the identity in activity records.
type tokenSource struct {
	token func() string
	label string
}

// resolveDeveloperTokenSource resolves the run's identity: an explicit --token/env, else the keyring
// login. No machine-identity path (that's for services, not a person on a laptop). Neither can be
// refreshed mid-session, so warnTokenExpiry flags when brokering will stop.
func resolveDeveloperTokenSource(cmd *cobra.Command) tokenSource {
	if token, err := util.GetInfisicalToken(cmd); err == nil && token != nil && token.Token != "" {
		warnTokenExpiry(token.Token, "the provided token")
		return tokenSource{token: func() string { return token.Token }, label: "token"}
	}

	details, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil || !details.IsUserLoggedIn || details.LoginExpired {
		details = util.EstablishUserLoginSession()
	}
	if details.UserCredentials.JTWToken == "" {
		util.HandleError(fmt.Errorf("could not resolve your Infisical login; run 'infisical login' or pass --token"))
	}
	jwt := details.UserCredentials.JTWToken
	warnTokenExpiry(jwt, "your login")
	return tokenSource{token: func() string { return jwt }, label: details.UserCredentials.Email}
}

// warnTokenExpiry prints when brokering will stop; silent when the expiry can't be read.
func warnTokenExpiry(jwtToken, subject string) {
	exp, ok := jwtExpiry(jwtToken)
	if !ok {
		return
	}
	remaining := time.Until(exp)
	if remaining <= 0 {
		util.PrintWarning(fmt.Sprintf("%s has expired; brokering will fail. Run 'infisical login' or pass a valid --token.", subject))
		return
	}
	util.PrintWarning(fmt.Sprintf("%s expires in %s (at %s); brokering stops then and cannot be refreshed mid-session. For a longer run, start fresh after 'infisical login'.",
		subject, remaining.Round(time.Minute), exp.Local().Format("15:04")))
}

// jwtExpiry reads the exp claim unverified; false if the token isn't a readable JWT (e.g. a service token).
func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

// fetchLocalProxiedServiceConfig returns the placeholder env to inject. No CanProxy filter (locally
// the gate is Read Value); disabled services are skipped. Real secret values are never fetched here.
func fetchLocalProxiedServiceConfig(httpClient *resty.Client, projectID, environment, secretPath string) map[string]string {
	resp, err := api.CallListProxiedServices(httpClient, api.ListProxiedServicesRequest{
		ProjectID:   projectID,
		Environment: environment,
		SecretPath:  secretPath,
	})
	if err != nil {
		util.HandleError(err, "Failed to list proxied services")
	}

	placeholders := map[string]string{}
	for _, svc := range resp.Services {
		if !svc.IsEnabled {
			continue
		}
		for _, cred := range svc.Credentials {
			if cred.Role == "credential-substitution" && cred.PlaceholderKey != "" {
				placeholders[cred.PlaceholderKey] = cred.PlaceholderValue
			}
		}
	}
	return placeholders
}

// defaultAgentStateWritePaths returns the supported agents' state paths under home that exist (only
// existing ones: bwrap --bind fails on a missing source).
func defaultAgentStateWritePaths(home string) []string {
	if home == "" {
		return nil
	}
	candidates := []string{
		filepath.Join(home, ".claude"),      // Claude Code state dir (sessions, history, cache)
		filepath.Join(home, ".claude.json"), // Claude Code top-level config
		filepath.Join(home, ".codex"),       // Codex state dir
	}
	var out []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// localProxyURL is the child's proxy URL: no userinfo, so no credential reaches the child.
func localProxyURL(proxyAddr string) string {
	u := url.URL{Scheme: "http", Host: proxyAddr}
	return u.String()
}

// infisicalAPIHost is the bare hostname of the configured Infisical API (the proxy refuses egress to it).
func infisicalAPIHost() string {
	u, err := url.Parse(config.INFISICAL_URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// buildLocalAgentEnv builds the child env: a scrubbed parent env (no INFISICAL_TOKEN/DOMAIN, no
// secret-shaped vars) plus the credential-free proxy vars, CA trust vars, and placeholders.
func buildLocalAgentEnv(cmd *cobra.Command, proxy, caPath string, placeholders map[string]string) []string {
	passEnv, _ := cmd.Flags().GetStringArray("pass-env")
	setEnv, _ := cmd.Flags().GetStringArray("set-env")

	allowlist := map[string]bool{}
	for _, k := range passEnv {
		allowlist[k] = true
	}

	stale := map[string]bool{}
	for _, k := range proxyEnvKeys {
		stale[k] = true
	}
	for _, k := range credentialEnvKeys {
		stale[k] = true
	}
	stale[util.INFISICAL_TOKEN_NAME] = true
	stale[util.INFISICAL_DOMAIN_ENV_NAME] = true
	stale[util.INFISICAL_VAULT_FILE_PASSPHRASE_ENV_NAME] = true

	var operatorNoProxy []string
	env := map[string]string{}
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if key == "NO_PROXY" || key == "no_proxy" {
			operatorNoProxy = append(operatorNoProxy, val)
			continue
		}
		if allowlist[key] {
			env[key] = val
			continue
		}
		if stale[key] || isSecretShapedEnvName(key) {
			continue
		}
		env[key] = val
	}

	env["HTTPS_PROXY"] = proxy
	env["HTTP_PROXY"] = proxy
	env["NO_PROXY"] = mergeNoProxy(operatorNoProxy...)
	env["NODE_USE_ENV_PROXY"] = "1"
	env["OPENCLAW_PROXY_URL"] = proxy

	for _, k := range caTrustEnvVars {
		env[k] = caPath
	}

	for k, v := range placeholders {
		env[k] = v
	}

	// --set-env wins last so operators can force a literal value into the child.
	for _, kv := range setEnv {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}

	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

func isSecretShapedEnvName(name string) bool {
	upper := strings.ToUpper(name)
	for _, s := range secretShapedEnvSubstrings {
		if strings.Contains(upper, s) {
			return true
		}
	}
	return false
}

func init() {
	agentProxyRunCmd.Flags().StringP("env", "e", "", "environment slug to fetch proxied services and secrets from")
	agentProxyRunCmd.Flags().String("path", "/", "secret path (folder) scope")
	agentProxyRunCmd.Flags().String("projectId", "", "project id (falls back to INFISICAL_PROJECT_ID or .infisical.json)")
	agentProxyRunCmd.Flags().String("token", "", "run with this token instead of your keyring login (used as-is; not refreshed)")
	agentProxyRunCmd.Flags().Bool("sandbox", true, "run the agent inside the OS sandbox (default on)")
	agentProxyRunCmd.Flags().Bool("no-sandbox", false, "disable the OS sandbox (agent runs uncontained; prints a warning)")
	agentProxyRunCmd.Flags().String("unmatched-host", "allow", "policy for hosts with no proxied service: allow | block")
	agentProxyRunCmd.Flags().Int("poll-interval", 60, "seconds between permission/credential refreshes")
	agentProxyRunCmd.Flags().String("log-file", "", "write the proxy activity log to this path (default: a per-run temp file, kept off the terminal)")
	agentProxyRunCmd.Flags().StringArray("allow-read", nil, "extra path the agent may read (repeatable)")
	agentProxyRunCmd.Flags().StringArray("allow-write", nil, "extra path the agent may write (repeatable; implies read)")
	agentProxyRunCmd.Flags().StringArray("allow-host", nil, "extra host the agent may reach through the proxy (repeatable)")
	agentProxyRunCmd.Flags().StringArray("pass-env", nil, "let a specific host env var through to the agent (repeatable)")
	agentProxyRunCmd.Flags().StringArray("set-env", nil, "inject a literal KEY=VALUE into the agent (repeatable)")
	// --proxy exists only so we can reject it with a helpful message pointing at connect.
	agentProxyRunCmd.Flags().String("proxy", "", "")
	_ = agentProxyRunCmd.Flags().MarkHidden("proxy")

	agentProxyCmd.AddCommand(agentProxyRunCmd)
}
