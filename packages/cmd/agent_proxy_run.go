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

// secretShapedEnvSubstrings drives the name-based env scrub: any parent env var whose name contains
// one of these (case-insensitive) is removed from the child env unless explicitly re-added with
// --pass-env. This is coarse on purpose (e.g. it scrubs ANTHROPIC_API_KEY); --pass-env is the escape.
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

	// Resolve the developer's identity. This is the single identity for the whole run: it fetches the
	// proxied-service config and the referenced secret values. The child gets none of it.
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

	// Per-run 0700 tempdir: only the public CA cert (and, on the Linux hard fence, the unix socket)
	// ever touch disk. Removed on exit.
	tempDir, err := os.MkdirTemp("", "infisical-agent-proxy-run-")
	if err != nil {
		util.HandleError(err, "Failed to create the per-run temp directory")
	}
	// os.Exit (at the end, and inside util.HandleError) does not run deferred funcs, so a `defer`
	// here would never fire. Clean up explicitly at each exit path instead. fail() removes the temp
	// dir before delegating to HandleError (which exits) so setup failures don't leak it either.
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	fail := func(e error, messages ...string) { cleanup(); util.HandleError(e, messages...) }

	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	extraRead, _ := cmd.Flags().GetStringArray("allow-read")
	extraWrite, _ := cmd.Flags().GetStringArray("allow-write")
	allowHosts, _ := cmd.Flags().GetStringArray("allow-host")

	// Supported interactive agents persist their own state under home (Claude Code: ~/.claude and
	// ~/.claude.json; Codex: ~/.codex). These are the agent's own data, not the developer's foreign
	// secrets, so making them writable is safe and is what a real interactive session needs (without
	// it Claude Code runs but cannot save sessions: "transcript writes are failing"). Reads there are
	// already allowed; only the write grant is missing by default.
	writePaths := append(defaultAgentStateWritePaths(home), extraWrite...)

	spec := sandbox.SandboxSpec{
		Sandbox:    sandboxEnabled,
		ReadPaths:  extraRead,
		WritePaths: writePaths,
		DenyPaths:  sandbox.DefaultDenyPaths(home),
		Cwd:        cwd,
		TempDir:    tempDir,
		AllowHosts: allowHosts,
		// HardFence is the default; the Linux backend downgrades to SharedNet via Preflight when
		// unprivileged user namespaces are restricted. macOS always fences egress to loopback via SBPL
		// regardless of this field.
		NetMode: sandbox.HardFence,
	}

	// Preflight decides sandbox availability and, on Linux, hard fence vs shared-net and whether the
	// in-namespace bridge is needed. It must run before we choose the proxy listener (unix socket vs
	// TCP) and build the child env (the proxy URL host/port depends on the bridge).
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

	// Choose the proxy transport. Hard fence: a pathname unix socket in the tempdir, bridged into the
	// empty netns; the child targets the bridge's fixed loopback port. Otherwise: TCP loopback the
	// child reaches directly (macOS SBPL, Linux shared-net, or --no-sandbox).
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
		log.Info().Msg(color.HiBlackString("Local coupled mode: the proxy acts with your own access and the OS sandbox is the boundary that keeps the agent from reading your credentials directly."))
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

// runSandboxedChild starts the child, forwards signals, and returns its exit code. If the proxy dies
// first, it kills the child (never leave the agent running against a dead proxy).
func runSandboxedChild(child *exec.Cmd, proxy *agentproxy.Proxy, proxyErrCh <-chan error) int {
	log.Info().Msg(color.GreenString("Starting agent behind the Infisical agent proxy (sandboxed)"))

	if err := child.Start(); err != nil {
		log.Error().Err(err).Msg("failed to start the agent process")
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
		log.Error().Err(err).Msg("the ephemeral proxy stopped unexpectedly; terminating the agent")
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
	log.Error().Err(err).Msg("agent process error")
	return 1
}

func shutdownProxy(proxy *agentproxy.Proxy) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxy.Shutdown(ctx)
}

// resolveSandboxEnabled reads the sandbox toggle from the flag or the env var only, never
// .infisical.json (a committed file must not be able to silently disable the boundary).
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

// tokenSource is the parent-held identity for a run. token() returns the current access token (read
// per API request, so a future user-session refresher can rotate it behind this accessor); label
// names the identity in activity records.
type tokenSource struct {
	token func() string
	label string
}

// resolveDeveloperTokenSource resolves the single identity for the run. Local mode is a human
// developer acting as themselves, so the only identities are the developer's keyring login or a token
// they already hold. There is intentionally no machine-identity path here: an MI is a
// service/automation identity (used by `agent-proxy start`, `gateway`, the agent daemon), not a
// person running an agent on their laptop.
//
//   - --token / env token: used as-is (a raw access token has no renewal material). Fails closed at
//     expiry, same as everywhere else in the CLI.
//   - Keyring login: the developer's own session. The CLI does not persist a usable refresh token for
//     user logins today (UserCredentials.RefreshToken is never populated at login), so this cannot be
//     refreshed mid-session either. Fails closed at expiry.
//
// A human's interactive session almost always fits inside the token's lifetime, so both paths just
// warn at startup how long brokering will last. Genuine long-session refresh would mean renewing the
// developer's own session (persist + use the login refresh token) and belongs in the shared login
// flow, not here.
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

// warnTokenExpiry prints how long brokering will last for a credential that cannot be refreshed, so a
// session outliving it is a conscious choice. Silent when the expiry can't be read or is comfortably far.
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

// jwtExpiry reads the exp claim from a JWT without verifying the signature (the token was already
// minted by Infisical). Returns false when the token is not a readable JWT (e.g. a service token).
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

// fetchLocalProxiedServiceConfig lists the proxied services in scope and returns the placeholder env
// to inject. Unlike the remote fetchProxiedServiceConfig it does NOT filter on CanProxy: locally the
// gate is Read Value alone. Disabled services are still skipped (their placeholders would reach
// upstream verbatim). Real secret values are never fetched here; brokering happens on the wire.
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

// defaultAgentStateWritePaths returns the supported agents' own state locations under home that
// currently exist, so an interactive agent can persist sessions/config. Only existing paths are
// returned: bwrap --bind fails on a missing source, and there is no reason to grant writes to a
// path the agent isn't using. These are the agent's own data, never the developer's other secrets.
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

// localProxyURL is the credential-free proxy URL for the child: no userinfo at all. The scope and the
// developer token live only in the parent; the child just needs to know where the proxy is.
func localProxyURL(proxyAddr string) string {
	u := url.URL{Scheme: "http", Host: proxyAddr}
	return u.String()
}

// infisicalAPIHost extracts the bare hostname of the configured Infisical API, used by the proxy to
// refuse egress to the control plane from inside the sandbox.
func infisicalAPIHost() string {
	u, err := url.Parse(config.INFISICAL_URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// buildLocalAgentEnv builds the child environment for local mode: the credential-free proxy vars, the
// CA trust vars, and the placeholders, on top of a scrubbed copy of the parent env. It deliberately
// omits INFISICAL_TOKEN, INFISICAL_DOMAIN, and every secret-shaped var, so no credential and no real
// secret ever reaches the agent through the environment. Brokered secrets reach it only on the wire.
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
