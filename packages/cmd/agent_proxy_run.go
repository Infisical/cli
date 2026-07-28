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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentproxy"
	"github.com/Infisical/infisical-merge/packages/api"
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

	// Same resolution order as `connect`: flag, then env var, then .infisical.json.
	environment := util.ResolveEnvironmentName(cmd)
	if environment == "" {
		util.HandleError(fmt.Errorf("the environment is required; pass --env, set INFISICAL_ENVIRONMENT, or set defaultEnvironment in .infisical.json"))
	}

	secretPath := util.ResolveSecretPath(cmd)

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
		ProjectID:    projectID,
		Environment:  environment,
		SecretPath:   secretPath,
		UserToken:    src.token,
		IdentityID:   src.label,
		IdentityName: src.label,
	}

	// Per-run 0700 tempdir: only the public CA cert (and the unix socket on the Linux hard fence) hit disk.
	tempDir, err := os.MkdirTemp("", "infisical-agent-proxy-run-")
	if err != nil {
		util.HandleError(err, "Failed to create the per-run temp directory")
	}
	// os.Exit (and util.HandleError) skip deferred funcs, so clean up explicitly at every exit path.
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	fail := func(e error, messages ...string) { cleanup(); util.HandleError(e, messages...) }

	// The agent owns the terminal, so proxy activity goes to a file instead of interleaving with its
	// output. --log-file pins a stable path; the default lives in the tempdir and dies with the run.
	// Errors and warnings still reach stderr independently.
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

	// macOS keeps the root under ~/.infisical (already sandbox-denied) so it can be trusted once in the
	// keychain, which is what Go tools like gh need. Elsewhere the injected CA env var is enough.
	if runtime.GOOS == "darwin" && home != "" {
		local.CADir = filepath.Join(home, ".infisical", "agent-proxy")
	}

	// The agent's own state dirs, so interactive sessions can save. Its data, not the developer's.
	writePaths := absolutePaths(append(defaultAgentStateWritePaths(home), extraWrite...))

	// --allow-read carves a read hole in the credential deny set, so name exactly what was re-opened.
	readExceptions := absolutePaths(extraRead)
	if sandboxEnabled && len(readExceptions) > 0 {
		util.PrintWarning(fmt.Sprintf("re-opened for reading inside the sandbox: %s. The agent can read these; they remain non-writable and their siblings stay denied.", strings.Join(readExceptions, ", ")))
	}

	spec := sandbox.Spec{
		Enabled:    sandboxEnabled,
		ReadPaths:  readExceptions,
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
		util.PrintWarning(fmt.Sprintf("network hard-fence unavailable (%s); falling back to shared host networking. The agent can now reach the network directly, so routing through the proxy is advisory (it relies on the proxy env vars) rather than enforced: a tool that ignores them will not be brokered. Credential controls are unaffected (env scrub, keyring block, filesystem deny).", pre.Reason))
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

	// Non-fatal by design: if the keychain install is declined, env-CA tools still work and only Go
	// tools lose brokering. securityd stays blocked either way, so the login token stays unreadable.
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
	}
	// Only worth printing when --log-file pins it somewhere that outlives the run.
	if logFile != "" {
		fmt.Fprintln(os.Stderr, color.HiBlackString("proxy activity log: "+logPath))
	}

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

	stopForwarding := sandbox.ForwardTerminationSignals(child)

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
		stopForwarding()
		code, ok := sandbox.WaitExitCode(err)
		if !ok {
			fmt.Fprintf(os.Stderr, "agent process error: %v\n", err)
		}
		return code
	}
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

// tokenSource is the parent-held identity for a run. label names it in activity records.
type tokenSource struct {
	token func() string
	label string
}

// resolveDeveloperTokenSource resolves the run's identity: --token if given, else the keyring login.
// There is no machine-identity path; that is for services, not a person on a laptop. Neither source
// refreshes mid-session, so we fail fast on an already-expired token.
func resolveDeveloperTokenSource(cmd *cobra.Command) tokenSource {
	if token, err := util.GetInfisicalToken(cmd); err == nil && token != nil && token.Token != "" {
		failIfTokenExpired(token.Token, "the provided token")
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
	failIfTokenExpired(jwt, "your login")
	return tokenSource{token: func() string { return jwt }, label: details.UserCredentials.Email}
}

// failIfTokenExpired aborts with a clear error when the token is already expired; silent otherwise
// (no routine "expires in Xh" banner). Tokens that aren't readable JWTs (e.g. service tokens) pass.
func failIfTokenExpired(jwtToken, subject string) {
	if exp, ok := jwtExpiry(jwtToken); ok && time.Until(exp) <= 0 {
		util.HandleError(fmt.Errorf("%s has expired; brokering would fail. Run 'infisical login' or pass a valid --token", subject))
	}
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

// absolutePaths resolves against the cwd and drops empties. SBPL `subpath` and bwrap `--ro-bind` both
// reject relative paths, so --allow-read ./creds would otherwise build a profile that fails to load.
func absolutePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		out = append(out, abs)
	}
	return out
}

// localProxyURL is the child's proxy URL: no userinfo, so no credential reaches the child.
func localProxyURL(proxyAddr string) string {
	u := url.URL{Scheme: "http", Host: proxyAddr}
	return u.String()
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
	for _, k := range authAgentEnvKeys {
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

	setProxyEnv(env, proxy, mergeNoProxy(operatorNoProxy...))

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
	agentProxyRunCmd.Flags().StringArray("allow-read", nil, "re-open a credential path the sandbox denies by default, read-only (repeatable; e.g. --allow-read ~/.aws/config)")
	agentProxyRunCmd.Flags().StringArray("allow-write", nil, "extra path the agent may write (repeatable; implies read)")
	agentProxyRunCmd.Flags().StringArray("allow-host", nil, "extra host the agent may reach through the proxy (repeatable)")
	agentProxyRunCmd.Flags().StringArray("pass-env", nil, "let a specific host env var through to the agent (repeatable)")
	agentProxyRunCmd.Flags().StringArray("set-env", nil, "inject a literal KEY=VALUE into the agent (repeatable)")
	// --proxy exists only so we can reject it with a helpful message pointing at connect.
	agentProxyRunCmd.Flags().String("proxy", "", "")
	_ = agentProxyRunCmd.Flags().MarkHidden("proxy")

	agentProxyCmd.AddCommand(agentProxyRunCmd)
}
