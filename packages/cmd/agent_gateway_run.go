package cmd

import (
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
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	sandboxEnvVar = "INFISICAL_AGENT_GATEWAY_SANDBOX"
	// Still honoured so an existing wrapper script does not silently start running agents uncontained.
	legacySandboxEnvVar = "INFISICAL_AGENT_PROXY_SANDBOX"
)

// secretShapedEnvSubstrings: env vars whose name contains any of these are scrubbed from the child
// (coarse on purpose; --pass-env re-admits a specific one).
var secretShapedEnvSubstrings = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY", "PRIVATE_KEY", "ACCESS_KEY",
}

// runLocalBroker brokers for one session in this process and runs the agent beside it, sandboxed. Local mode
// resolves credentials under the caller's own permissions because the broker shares the caller's process:
// there is no boundary between them, and the sandbox is what keeps the *agent* away from the plaintext.
func runLocalBroker(cmd *cobra.Command, args []string, session localBrokerSession, endSession func()) {
	unmatchedHost, _ := cmd.Flags().GetString("unmatched-host")
	if unmatchedHost != agentproxy.UnmatchedAllow && unmatchedHost != agentproxy.UnmatchedBlock {
		util.HandleError(fmt.Errorf("--unmatched-host must be 'allow' or 'block', got %q", unmatchedHost))
	}

	sandboxEnabled := resolveSandboxEnabled(cmd)

	// Per-run 0700 tempdir: only the public CA cert (and the unix socket on the Linux hard fence) hit disk.
	tempDir, err := os.MkdirTemp("", "infisical-agent-gateway-run-")
	if err != nil {
		util.HandleError(err, "Unable to create a temporary directory")
	}
	// os.Exit (and util.HandleError) skip deferred funcs, so clean up explicitly at every exit path.
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
		// os.Exit and util.HandleError both skip deferred funcs, so the session is ended here rather than
		// left for the backend's expiry sweep.
		if endSession != nil {
			endSession()
		}
	}
	fail := func(e error, messages ...string) { cleanup(); util.HandleError(e, messages...) }

	// Nothing is written unless --log-file asks for it: a file the operator did not request is one they
	// cannot find, and on a tmpfs /tmp it would be memory. Without it, problems still surface on stderr
	// while per-request activity is dropped, so an agent's TUI stays intact. An explicit --log-level
	// overrides that filter for anyone debugging without a file.
	logFile, _ := cmd.Flags().GetString("log-file")
	if logFile != "" {
		logF, logErr := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if logErr != nil {
			fail(logErr, "Unable to open the log file")
		}
		log.Logger = log.Output(GetLoggerConfig(logF, true))
	} else {
		log.Logger = log.Output(GetLoggerConfig(os.Stderr, !isatty.IsTerminal(os.Stderr.Fd())))
		if !cmd.Flags().Changed("log-level") && os.Getenv("LOG_LEVEL") == "" {
			log.Logger = log.Logger.Level(zerolog.WarnLevel)
		}
	}

	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	extraRead, _ := cmd.Flags().GetStringArray("allow-read")
	extraWrite, _ := cmd.Flags().GetStringArray("allow-write")
	allowHosts, _ := cmd.Flags().GetStringArray("allow-host")

	// macOS keeps the root under ~/.infisical (already sandbox-denied) so it can be trusted once in the
	// keychain, which is what Go tools like gh need. Elsewhere the injected CA env var is enough.
	caDir := ""
	if runtime.GOOS == "darwin" && home != "" {
		caDir = filepath.Join(home, ".infisical", "agent-gateways")
	}

	// The agent's own state dirs, so interactive sessions can save. Its data, not the developer's.
	writePaths := absolutePaths(append(sandbox.AgentStateWritePaths(home), extraWrite...))

	// --allow-read carves a read hole in the credential deny set, so name exactly what was re-opened.
	readExceptions := absolutePaths(extraRead)
	if sandboxEnabled && len(readExceptions) > 0 {
		util.PrintWarning(fmt.Sprintf("The agent can now read %s. These paths stay read-only.", strings.Join(readExceptions, ", ")))
	}

	spec := sandbox.Spec{
		Enabled:    sandboxEnabled,
		ReadPaths:  readExceptions,
		WritePaths: writePaths,
		DenyPaths:  sandbox.DefaultDenyPaths(home, sandbox.HostRuntimeDir()),
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
		fail(err, "Unable to check sandbox support on this host")
	}
	if !pre.Supported {
		fail(fmt.Errorf("%s", pre.Reason))
	}
	if pre.FallbackToSharedNet {
		spec.NetMode = sandbox.SharedNet
		util.PrintWarning(fmt.Sprintf("Unable to isolate the network on this host (%s), the agent will share your network connection. Requests are still routed through the broker, but a program that ignores the proxy settings can reach the network directly. Credential protections are unchanged.", pre.Reason))
	}

	// After preflight so a downgraded fence is visible; before brokering starts so a run that dies still counts.
	passEnv, _ := cmd.Flags().GetStringArray("pass-env")
	setEnv, _ := cmd.Flags().GetStringArray("set-env")
	Telemetry.SetActor(telemetry.IdentityClaimsFromToken(session.Token()))
	Telemetry.CaptureEvent("cli-command:agent gateway run", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("agent", telemetryAgentName(args)).
		Set("platform", runtime.GOOS).
		Set("sandboxEnabled", sandboxEnabled).
		Set("sandboxSource", sandboxSource(cmd)).
		Set("netDowngraded", pre.FallbackToSharedNet).
		Set("unmatchedHost", unmatchedHost).
		Set("allowReadCount", len(extraRead)).
		Set("allowWriteCount", len(extraWrite)).
		Set("allowHostCount", len(allowHosts)).
		Set("passEnvCount", len(passEnv)).
		Set("setEnvCount", len(setEnv)))

	// The secret in the proxy URL is what stops another process on this machine using the listener. The
	// sandbox already fences the agent, but --no-sandbox, and the shared-network fallback, do not.
	localSecret := util.GenerateRandomString(32)

	broker, err := agentproxy.NewBroker(agentproxy.BrokerOptions{
		Token:         session.Token,
		UnmatchedHost: unmatchedHost,
		ProxySecret:   localSecret,
		LocalCADir:    caDir,
		UseLocalCA:    true,
	})
	if err != nil {
		fail(err, "Unable to start the local broker")
	}

	brokerSession := agentproxy.Session{
		ID:               session.ID,
		AgentGatewayID:   session.AgentGatewayID,
		AgentGatewayName: session.AgentGatewayName,
		ActorName:        session.ActorName,
		ExpiresAt:        session.ExpiresAt,
		UnmatchedHost:    unmatchedHost,
		AllowedHosts:     allowHosts,
	}

	// Non-fatal by design: if the keychain install is declined, env-CA tools still work and only Go
	// tools lose brokering. securityd stays blocked either way, so the login token stays unreadable.
	if caDir != "" {
		if sandboxEnabled {
			spec.AllowTrustd = true
		}
		switch installed, terr := ensureCATrusted(agentproxy.LocalCACertPath(caDir)); {
		case terr != nil:
			util.PrintWarning(fmt.Sprintf("Unable to add the Infisical broker CA to your login keychain (%v). Most tools will still work, but some may report a certificate error.", terr))
		case installed:
			util.PrintWarning("Added the Infisical broker CA to your login keychain. This is one-time and persists for future runs.")
		}
	}

	// Hard fence: broker on a unix socket in the tempdir, reached via the bridge. Otherwise: TCP loopback.
	var listener net.Listener
	var childProxyHost string
	if pre.UsesBridge {
		spec.ProxySocket = filepath.Join(tempDir, "proxy.sock")
		listener, err = net.Listen("unix", spec.ProxySocket)
		if err != nil {
			fail(err, "Unable to start the local broker listener")
		}
		spec.LoopbackPort = sandbox.BridgeLoopbackPort
		childProxyHost = fmt.Sprintf("127.0.0.1:%d", sandbox.BridgeLoopbackPort)
	} else {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fail(err, "Unable to start the local broker listener")
		}
		spec.LoopbackPort = listener.Addr().(*net.TCPAddr).Port
		childProxyHost = listener.Addr().String()
	}

	caPath := filepath.Join(tempDir, "broker-ca.pem")
	if err := os.WriteFile(caPath, broker.RootPEM(), 0o600); err != nil {
		fail(err, "Unable to write the CA certificate")
	}

	brokerErrCh := make(chan error, 1)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				brokerErrCh <- acceptErr
				return
			}
			go broker.ServeConn(conn, brokerSession)
		}
	}()

	spec.Env = buildLocalAgentEnv(cmd, localProxyURL(childProxyHost, localSecret), caPath, session.Placeholders)

	if !sandboxEnabled {
		util.PrintWarning("Running without the OS sandbox. The agent can read your keyring and credential files and reach the network directly. Credentials are still brokered on the wire.")
	}
	if logFile != "" {
		fmt.Fprintln(os.Stderr, color.HiBlackString("broker activity log: "+logFile))
	}

	child, err := backend.Wrap(spec, args)
	if err != nil {
		broker.Close()
		fail(err, "Unable to start the agent in the sandbox")
	}

	exitCode := runSandboxedChild(child, broker, brokerErrCh)
	_ = listener.Close()
	broker.Close()
	cleanup()
	os.Exit(exitCode)
}

// runSandboxedChild starts the child, forwards signals, and returns its exit code; if the broker's listener
// dies first it kills the child rather than leaving it running with no route out.
func runSandboxedChild(child *exec.Cmd, broker *agentproxy.Broker, brokerErrCh <-chan error) int {
	fmt.Fprintln(os.Stderr, color.GreenString("Starting agent with its requests brokered on this machine (sandboxed)"))

	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start the agent process: %v\n", err)
		return 1
	}

	stopForwarding := sandbox.ForwardTerminationSignals(child)

	waitCh := make(chan error, 1)
	go func() { waitCh <- child.Wait() }()

	select {
	case err := <-brokerErrCh:
		fmt.Fprintf(os.Stderr, "%s\n", color.RedString("the local broker stopped unexpectedly (%v); terminating the agent", err))
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

// Mirrors resolveSandboxEnabled's order, so a deliberate opt-out is distinguishable from the default.
func sandboxSource(cmd *cobra.Command) string {
	switch {
	case cmd.Flags().Changed("sandbox"), cmd.Flags().Changed("no-sandbox"):
		return "flag"
	case os.Getenv(sandboxEnvVar) != "", os.Getenv(legacySandboxEnvVar) != "":
		return "env"
	default:
		return "default"
	}
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
	for _, name := range []string{sandboxEnvVar, legacySandboxEnvVar} {
		if v := os.Getenv(name); v != "" {
			return !(v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off"))
		}
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
// One chain for both modes, so a credential that works for connect also works for run. Neither source
// refreshes mid-session, so an already-expired token fails fast rather than at the first brokered request.
func resolveDeveloperTokenSource(cmd *cobra.Command) tokenSource {
	token, label, err := resolveAgentGatewayToken(cmd)
	if err == nil && token != nil && token.Token != "" {
		failIfTokenExpired(token.Token, "your credentials")
		return tokenSource{token: func() string { return token.Token }, label: label}
	}

	// Local mode is interactive by definition, so an absent login is worth prompting for rather than failing.
	details := util.EstablishUserLoginSession()
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

// localProxyURL is the child's proxy URL. The userinfo carries this run's listener secret, which is
// meaningless outside this process: it authorizes use of the listener, not access to any credential.
func localProxyURL(proxyAddr, secret string) string {
	u := url.URL{Scheme: "http", User: url.UserPassword("session", secret), Host: proxyAddr}
	return u.String()
}

// buildLocalAgentEnv builds the child env: a scrubbed parent env (no INFISICAL_TOKEN/DOMAIN, no
// secret-shaped vars) plus the credential-free proxy vars, CA trust vars, and placeholders.
func buildLocalAgentEnv(cmd *cobra.Command, proxy, caPath string, placeholders []agentproxy.Placeholder) []string {
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
	// The long-lived machine identity credentials, so the agent never inherits an identity of its own.
	stale[util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME] = true
	stale[util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME] = true
	stale[util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME] = true
	for _, k := range authAgentEnvKeys {
		stale[k] = true
	}
	stale[util.INFISICAL_TOKEN_NAME] = true
	// INFISICAL_JWT authenticates a JWT/OIDC machine identity, so it is as good as a token here and
	// matches none of the secret-shaped name patterns.
	stale[util.INFISICAL_JWT_NAME] = true
	stale[util.INFISICAL_OIDC_AUTH_JWT_NAME] = true
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

	for _, placeholder := range placeholders {
		env[placeholder.Key] = placeholder.Value
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
