package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	infisicalSdk "github.com/infisical/go-sdk"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var agentProxyCmd = &cobra.Command{
	Use:                   "agent-proxy",
	Short:                 "Secrets brokering: run an agent proxy and connect agents to it",
	DisableFlagsInUseLine: true,
}

var agentProxyConnectCmd = &cobra.Command{
	Use:   "connect [flags] -- [agent start command]",
	Short: "Set up the environment and launch an agent behind the agent proxy",
	Example: `# With flags
infisical secrets agent-proxy connect --proxy=<proxy-host>:17322 --projectId=<project-id> --env=prod --path=/myapp -- claude

# With environment variables (INFISICAL_PROJECT_ID, INFISICAL_ENVIRONMENT, INFISICAL_SECRET_PATH, INFISICAL_AGENT_PROXY_ADDRESS)
infisical secrets agent-proxy connect -- claude`,
	DisableFlagsInUseLine: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("provide the agent command to run after '--', e.g. -- claude")
		}
		return nil
	},
	Run: runAgentProxyConnect,
}

var agentProxyStartCmd = &cobra.Command{
	Use:                   "start",
	Short:                 "Start the agent proxy (MITM proxy that brokers credentials on the wire)",
	Example:               "infisical secrets agent-proxy start --port 17322",
	DisableFlagsInUseLine: true,
	Run:                   runAgentProxyStart,
}

const mitmCaRelativePath = ".infisical/agent-proxy/mitm-ca.pem"

var caTrustEnvVars = []string{
	"SSL_CERT_FILE",
	"NODE_EXTRA_CA_CERTS",
	"REQUESTS_CA_BUNDLE",
	"CURL_CA_BUNDLE",
	"GIT_SSL_CAINFO",
	"DENO_CERT",
}

// Stripped as well as set: getenv returns the first match, so stale copies must be removed.
var proxyEnvKeys = []string{
	"HTTPS_PROXY",
	"https_proxy",
	"HTTP_PROXY",
	"http_proxy",
	"NO_PROXY",
	"no_proxy",
	"NODE_USE_ENV_PROXY",
	"OPENCLAW_PROXY_URL",
}

// Stripped so the agent is handed only the scoped short-lived JWT set below, and not whatever the
// parent authenticated with.
//
// Derived from util.MachineIdentityAuthEnvVars rather than listed here, so that a machine identity
// auth method added to the CLI cannot quietly widen what the agent inherits. INFISICAL_AUTH_METHOD is
// in that list and matters as much as the credentials: connect deliberately sets INFISICAL_TOKEN for
// the agent, and a stray auth method would send a CLI call inside the agent down a machine identity
// login instead of using that token.
//
// How much this is worth depends on the method. For universal-auth, ldap-auth and the jwt-based
// methods the credential is a value that lives only in the environment, so removing it is a real
// boundary. For kubernetes, aws-iam, azure and gcp-id-token the credential is an ambient capability of
// the host (a service account token file, an instance metadata endpoint) that the agent can reach
// whether or not it inherits these; there the isolation comes from the agent running on a different
// host to the proxy, and from the agent identity holding Proxy and nothing else.
var credentialEnvKeys = append([]string{
	util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME,
}, util.MachineIdentityAuthEnvVars...)

// Addresses of host IPC endpoints. Not secret values, but handing them to the agent points it at
// sockets it can use: the SSH/GPG agents as a signing oracle, and the session bus, where
// systemd --user StartTransientUnit runs a process outside the sandbox. Unix sockets are not
// namespaced, so on Linux dropping these is what keeps them out of reach.
// Scrubbed by default; --pass-env re-admits a specific one.
var authAgentEnvKeys = []string{
	"SSH_AUTH_SOCK",
	"SSH_AGENT_PID",
	"GPG_AGENT_INFO",
	"DBUS_SESSION_BUS_ADDRESS",
	"DBUS_SYSTEM_BUS_ADDRESS",
	"XDG_RUNTIME_DIR",
}

var requiredNoProxy = []string{"localhost", "127.0.0.1"}

// setProxyEnv points the child's HTTP clients at the proxy. Both letter cases are set on purpose:
// curl honours only the lowercase http_proxy for plain-HTTP URLs, so an uppercase-only environment
// sends those requests to DNS instead of the proxy. Shared by connect and run so the two can't drift.
func setProxyEnv(env map[string]string, proxyURL, noProxy string) {
	env["HTTP_PROXY"] = proxyURL
	env["http_proxy"] = proxyURL
	env["HTTPS_PROXY"] = proxyURL
	env["https_proxy"] = proxyURL
	env["NO_PROXY"] = noProxy
	env["no_proxy"] = noProxy
	env["NODE_USE_ENV_PROXY"] = "1"
	env["OPENCLAW_PROXY_URL"] = proxyURL
}

func mergeNoProxy(operatorEntries ...string) string {
	seen := make(map[string]bool)
	var merged []string
	add := func(raw string) {
		for _, entry := range strings.Split(raw, ",") {
			if entry = strings.TrimSpace(entry); entry != "" && !seen[entry] {
				seen[entry] = true
				merged = append(merged, entry)
			}
		}
	}
	for _, d := range requiredNoProxy {
		add(d)
	}
	for _, o := range operatorEntries {
		add(o)
	}
	return strings.Join(merged, ",")
}

func runAgentProxyConnect(cmd *cobra.Command, args []string) {
	proxyAddr := util.ResolveAgentProxyAddress(cmd)
	if proxyAddr == "" {
		util.HandleError(fmt.Errorf("the agent proxy address is required; pass --proxy or set INFISICAL_AGENT_PROXY_ADDRESS (e.g. <proxy-host>:17322)"))
	}

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

	token, tokenSource := resolveAgentToken(cmd)

	allowReadableBrokered := util.GetBoolFlagOrEnv(cmd, "allow-readable-brokered-secrets", util.INFISICAL_AGENT_PROXY_ALLOW_READABLE_BROKERED_SECRETS_NAME)

	Telemetry.SetActor(telemetry.IdentityClaimsFromToken(token.Token))
	Telemetry.CaptureEvent("cli-command:agent-proxy connect", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("agent", telemetryAgentName(args)).
		Set("credentialSource", tokenSource).
		Set("allowReadableBrokeredSecrets", allowReadableBrokered))

	httpClient := resty.New().SetAuthToken(token.Token)

	caResp, err := api.CallGetAgentProxyCa(httpClient)
	if err != nil {
		util.HandleError(err, "Failed to fetch the agent proxy root CA")
	}
	caPath, err := writeMitmCa(caResp.Certificate)
	if err != nil {
		util.HandleError(err, "Failed to write the agent proxy CA to disk")
	}

	placeholderEnvs, brokeredKeys, leasableDynamicCreds := fetchProxiedServiceConfig(httpClient, projectID, environment, secretPath)

	realSecrets := fetchAgentRealSecrets(token, projectID, environment, secretPath)

	if !allowReadableBrokered {
		// static readability is derived from realSecrets we already fetch; dynamic lease-ability comes from
		// the server (callerCanLease) since we don't fetch dynamic secrets here.
		assertNoBrokeredSecretsReadable(brokeredKeys, realSecrets)
		assertNoBrokeredDynamicSecretsLeasable(leasableDynamicCreds)
	}

	extraNoProxy, _ := cmd.Flags().GetString("no-proxy")
	env := buildAgentEnv(proxyURL(proxyAddr, projectID, environment, secretPath, token.Token), caPath, token.Token, extraNoProxy, placeholderEnvs, realSecrets)

	if err := runAgentProcess(args, env); err != nil {
		util.HandleError(err, "Agent process failed")
	}
}

// Only the executable name: argv past the first word routinely carries credentials.
func telemetryAgentName(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return filepath.Base(args[0])
}

// resolveAgentProxyStaticToken returns a token the operator fetched elsewhere, or nil if none was
// given. The two guards match what `pam agentic-access` applies to the same input: a service token
// authenticates to the secrets API but not as a machine identity, so it cannot stand in for one here,
// and an expired token is worth catching now rather than at the agent's first proxied request, which
// is where it would otherwise surface as an unexplained 403.
func resolveAgentProxyStaticToken(cmd *cobra.Command, subject string) *models.TokenDetails {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to resolve authentication")
	}
	if token == nil {
		return nil
	}
	if token.Type == util.SERVICE_TOKEN_IDENTIFIER {
		util.PrintErrorMessageAndExit("The agent proxy does not support service tokens. Use a machine identity access token, or authenticate with --auth-method.")
	}
	failIfTokenExpired(token.Token, subject)
	return token
}

// agentProxyCredential is how a command authenticates. Exactly one of token and login is set, unless
// nothing was configured at all, in which case neither is.
type agentProxyCredential struct {
	token  *models.TokenDetails
	login  func() (infisicalSdk.MachineIdentityCredential, error)
	source string
}

// machineIdentityGivenAsFlag reports whether this invocation named a machine identity on the command
// line, rather than inheriting one from the environment.
func machineIdentityGivenAsFlag(cmd *cobra.Command) bool {
	return cmd.Flags().Changed("auth-method") ||
		cmd.Flags().Changed("client-id") ||
		cmd.Flags().Changed("client-secret")
}

// resolveAgentProxyCredential chooses between a token the operator already has and a machine identity
// that authenticates itself.
//
// A ready-made token comes first, as it does in `pam agentic-access`. The exception is a flag that was
// actually typed: --auth-method or client credentials on the command line beat a token that came only
// from the environment. Without that exception INFISICAL_TOKEN would win, and it is the variable most
// likely to be exported for something else entirely, not least because `connect` sets it in every
// agent environment it launches.
func resolveAgentProxyCredential(cmd *cobra.Command) agentProxyCredential {
	tokenFirst := cmd.Flags().Changed("token") || !machineIdentityGivenAsFlag(cmd)

	if tokenFirst {
		if token := resolveAgentProxyStaticToken(cmd, "the provided token"); token != nil {
			return agentProxyCredential{token: token, source: "token"}
		}
	}

	if login, source := resolveAgentProxyLogin(cmd); login != nil {
		return agentProxyCredential{login: login, source: source}
	}

	// Only reachable when a machine identity was named on the command line but resolved to nothing,
	// which resolveAgentProxyLogin already rejects. Kept so the token is never dropped silently.
	if !tokenFirst {
		if token := resolveAgentProxyStaticToken(cmd, "the provided token"); token != nil {
			return agentProxyCredential{token: token, source: "token"}
		}
	}

	return agentProxyCredential{}
}

// resolveAgentProxyLogin works out how this command's machine identity authenticates, and returns a
// function that performs one authentication per call along with a label naming the branch for
// telemetry. Both are nil when nothing was configured.
//
// The order within this function is an explicit --auth-method, then client credentials on their own as
// the shorthand for universal-auth. resolveAgentProxyCredential decides how this ranks against a
// ready-made token.
//
// Each call builds its own SDK client and lets it go again. The SDK cannot be told to skip its
// background token lifecycle (Config.AutoTokenRefresh is a bool tagged `default:"true"`, and
// setDefaults rewrites any false bool back to its default). Left alive, that goroutine would
// re-authenticate on its own schedule alongside the renewal the caller is already driving, doubling
// this identity's authentication events; a client that dies with its login cannot. Separately, and
// the reason nothing here returns the SDK's own getter: that goroutine renews into a field
// Auth().GetAccessToken reads without taking the client's mutex, and both commands read the token
// from a per-request path.
func resolveAgentProxyLogin(cmd *cobra.Command) (login func() (infisicalSdk.MachineIdentityCredential, error), source string) {
	authMethod, err := util.ResolveAuthMethod(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse auth-method flag")
	}

	if authMethod == "" {
		clientID, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME}, "")
		clientSecret, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME}, "")
		if clientID == "" && clientSecret == "" {
			return nil, ""
		}
		// Half a credential is a mistake rather than a request for a different method, and saying which
		// half is missing beats listing every method the command accepts.
		if clientID == "" {
			util.HandleError(fmt.Errorf("client id required; pass --client-id or set %s", util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME))
		}
		if clientSecret == "" {
			util.HandleError(fmt.Errorf("client secret required; pass --client-secret or set %s", util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME))
		}
		authMethod = string(util.AuthStrategy.UNIVERSAL_AUTH)
	}

	// Rejected here rather than at the first login, so that a typo fails before the command has done
	// anything else.
	if err := util.ValidateAuthMethod(authMethod); err != nil {
		util.PrintErrorMessageAndExit(err.Error())
	}

	customHeaders, err := util.GetInfisicalCustomHeadersMap()
	if err != nil {
		util.HandleError(err, "Unable to get custom headers")
	}

	login = func() (infisicalSdk.MachineIdentityCredential, error) {
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		client := infisicalSdk.NewInfisicalClient(ctx, infisicalSdk.Config{
			SiteUrl:       config.INFISICAL_URL,
			UserAgent:     api.USER_AGENT,
			CustomHeaders: customHeaders,
		})
		authenticate, err := util.MachineIdentityLoginFunc(cmd, client, authMethod)
		if err != nil {
			return infisicalSdk.MachineIdentityCredential{}, err
		}
		credential, err := authenticate()
		if err != nil {
			return infisicalSdk.MachineIdentityCredential{}, err
		}
		if credential.AccessToken == "" {
			return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("authenticating with %s returned no access token", authMethod)
		}
		return credential, nil
	}
	return login, authMethodCredentialSource(cmd, authMethod)
}

// authMethodCredentialSource labels how the identity was configured, for telemetry. The method alone
// would not distinguish the two ways of asking for the same one.
func authMethodCredentialSource(cmd *cobra.Command, authMethod string) string {
	if cmd.Flags().Changed("auth-method") || cmd.Flags().Changed("client-id") {
		return authMethod + "-flag"
	}
	return authMethod + "-env"
}

// Returns the token and a label for the branch that produced it.
//
// Whichever branch wins, the token is frozen here: connect writes it into the agent's environment and
// execs, and nothing can reach in and rewrite it afterwards. When it expires the agent's requests
// start coming back 403 and the agent has to be relaunched.
func resolveAgentToken(cmd *cobra.Command) (*models.TokenDetails, string) {
	resolved := resolveAgentProxyCredential(cmd)
	if resolved.token != nil {
		return resolved.token, resolved.source
	}
	if resolved.login == nil {
		util.HandleError(fmt.Errorf("authentication required; pass --auth-method [%s] with that method's credentials, --client-id/--client-secret, or a token", util.MachineIdentityAuthMethods))
	}

	credential, err := resolved.login()
	if err != nil {
		util.HandleError(err, "Failed to authenticate the agent machine identity")
	}
	return &models.TokenDetails{
		Type:  util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER,
		Token: credential.AccessToken,
	}, resolved.source
}

// Builds http://<projectId>:<env>/<path>:<jwt>@host:port (username=projectId, password="<env>/<path>:<jwt>", jwt last).
func proxyURL(proxyAddr, projectID, environment, secretPath, jwt string) string {
	password := fmt.Sprintf("%s/%s:%s", environment, strings.TrimPrefix(secretPath, "/"), jwt)
	u := url.URL{
		Scheme: "http",
		User:   url.UserPassword(projectID, password),
		Host:   proxyAddr,
	}
	return u.String()
}

func writeMitmCa(certificatePem string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	caPath := filepath.Join(home, mitmCaRelativePath)
	if err := os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(caPath, []byte(certificatePem), 0o600); err != nil {
		return "", err
	}
	return caPath, nil
}

// fetchProxiedServiceConfig lists the proxied services the agent can reach and returns both the
// credential-substitution placeholders to inject and the set of secret keys those services broker. The
// brokered keys are what the agent is meant to receive only through the proxy, never as real values.
type leasableDynamicCred struct {
	dynamicSecretName string
}

func fetchProxiedServiceConfig(httpClient *resty.Client, projectID, environment, secretPath string) (map[string]string, map[string]struct{}, []leasableDynamicCred) {
	resp, err := api.CallListProxiedServices(httpClient, api.ListProxiedServicesRequest{
		ProjectID:   projectID,
		Environment: environment,
		SecretPath:  secretPath,
	})
	if err != nil {
		util.HandleError(err, "Failed to list proxied services")
	}

	placeholders := map[string]string{}
	brokeredKeys := map[string]struct{}{}
	var leasable []leasableDynamicCred
	for _, svc := range resp.Services {
		// Disabled services aren't proxied, so their placeholders would reach upstream verbatim; don't inject them.
		if !svc.CanProxy || !svc.IsEnabled {
			continue
		}
		for _, cred := range svc.Credentials {
			if cred.DynamicSecretName != "" && cred.CallerCanLease {
				leasable = append(leasable, leasableDynamicCred{dynamicSecretName: cred.DynamicSecretName})
			}
			if cred.SecretKey != "" {
				brokeredKeys[cred.SecretKey] = struct{}{}
			}
			if cred.Role == "credential-substitution" && cred.PlaceholderKey != "" {
				placeholders[cred.PlaceholderKey] = cred.PlaceholderValue
			}
		}
	}
	return placeholders, brokeredKeys, leasable
}

// assertNoBrokeredDynamicSecretsLeasable is the dynamic-secret counterpart of assertNoBrokeredSecretsReadable:
// the agent holding Lease on a brokered dynamic secret can mint it directly, bypassing the proxy, so fail fast.
func assertNoBrokeredDynamicSecretsLeasable(leasable []leasableDynamicCred) {
	if len(leasable) == 0 {
		return
	}
	seen := map[string]struct{}{}
	var names []string
	for _, l := range leasable {
		if _, ok := seen[l.dynamicSecretName]; ok {
			continue
		}
		seen[l.dynamicSecretName] = struct{}{}
		names = append(names, l.dynamicSecretName)
	}
	sort.Strings(names)
	util.HandleError(fmt.Errorf(
		"the agent can lease dynamic secret(s) that are brokered by a proxied service: %s\n"+
			"brokering hides these values from the agent, but it has Lease on them and would mint them directly, bypassing the proxy.\n"+
			"fix: remove the agent's Lease permission on these dynamic secrets, or stop referencing them from proxied services.\n"+
			"to start anyway, pass --allow-readable-brokered-secrets",
		strings.Join(names, ", ")))
}

// assertNoBrokeredSecretsReadable fails fast when the agent can read a secret that a proxied service
// brokers to it. Brokering is meant to keep the real value out of the agent's hands, but if the agent
// also holds ReadValue on that secret it gets the value directly (delivered here as a real secret, and
// readable straight from the API), so the protection is silently bypassed. This is a misconfiguration
// guardrail, not a security boundary: the real fix is to not grant the agent ReadValue on brokered secrets.
func readableBrokeredSecrets(brokeredKeys map[string]struct{}, realSecrets []models.SingleEnvironmentVariable) []string {
	var overlap []string
	for _, s := range realSecrets {
		if _, ok := brokeredKeys[s.Key]; ok {
			overlap = append(overlap, s.Key)
		}
	}
	sort.Strings(overlap)
	return overlap
}

func assertNoBrokeredSecretsReadable(brokeredKeys map[string]struct{}, realSecrets []models.SingleEnvironmentVariable) {
	overlap := readableBrokeredSecrets(brokeredKeys, realSecrets)
	if len(overlap) == 0 {
		return
	}
	util.HandleError(fmt.Errorf(
		"the agent can read secret(s) that are brokered by a proxied service: %s\n"+
			"brokering hides these values from the agent, but it has ReadValue on them and would receive them directly, bypassing the proxy.\n"+
			"fix: remove the agent's ReadValue permission on these secrets, or stop referencing them from proxied services.\n"+
			"to start anyway, pass --allow-readable-brokered-secrets",
		strings.Join(overlap, ", ")))
}

func fetchAgentRealSecrets(token *models.TokenDetails, projectID, environment, secretPath string) []models.SingleEnvironmentVariable {
	params := models.GetAllSecretsParameters{
		Environment:            environment,
		WorkspaceId:            projectID,
		SecretsPath:            secretPath,
		ExpandSecretReferences: true,
		IncludeImport:          true,
	}
	// Always an identity access token: resolveAgentProxyStaticToken turns a service token away, and
	// every auth method produces one of these.
	params.UniversalAuthAccessToken = token.Token

	secrets, err := util.GetAllEnvironmentVariables(params, "")
	if err != nil {
		// A 401/403 just means the agent can't read any secret in this scope (normal when it only holds
		// Proxy access): there's nothing to deliver and nothing is wrong, so say nothing. Only a genuine
		// failure (network, server error) is worth surfacing.
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 403) {
			log.Debug().Msg("Agent has no readable secrets in this scope; skipping real-secret delivery")
		} else {
			log.Warn().Msgf("Could not fetch the agent's readable secrets: %v", err)
		}
		return nil
	}
	return secrets
}

func buildAgentEnv(proxy, caPath, jwt, extraNoProxy string, placeholders map[string]string, realSecrets []models.SingleEnvironmentVariable) []string {
	stale := map[string]bool{}
	for _, k := range proxyEnvKeys {
		stale[k] = true
	}
	for _, k := range credentialEnvKeys {
		stale[k] = true
	}
	var operatorNoProxy []string
	env := map[string]string{}
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "NO_PROXY" || parts[0] == "no_proxy" {
			operatorNoProxy = append(operatorNoProxy, parts[1])
			continue
		}
		if !stale[parts[0]] {
			env[parts[0]] = parts[1]
		}
	}

	setProxyEnv(env, proxy, mergeNoProxy(append(operatorNoProxy, extraNoProxy)...))

	for _, k := range caTrustEnvVars {
		env[k] = caPath
	}

	env["INFISICAL_TOKEN"] = jwt
	env[util.INFISICAL_DOMAIN_ENV_NAME] = strings.TrimSuffix(config.INFISICAL_URL, "/api")

	for k, v := range placeholders {
		env[k] = v
	}

	for _, s := range realSecrets {
		if _, collides := placeholders[s.Key]; collides {
			log.Warn().Msgf("Secret %q shadows a proxied-service placeholder; using the real secret value", s.Key)
		}
		env[s.Key] = s.Value
	}

	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

func runAgentProcess(args, env []string) error {
	log.Info().Msg(color.GreenString("Starting agent behind the Infisical agent proxy"))

	// #nosec G204 -- the command is provided directly by the operator running the CLI
	proc := exec.Command(args[0], args[1:]...)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	proc.Env = env

	if err := proc.Start(); err != nil {
		return err
	}

	stopForwarding := sandbox.ForwardTerminationSignals(proc)
	err := proc.Wait()
	stopForwarding()
	if err == nil {
		return nil
	}
	if code, ok := sandbox.WaitExitCode(err); ok {
		os.Exit(code)
	}
	return err
}

func init() {
	agentProxyConnectCmd.Flags().String("proxy", "", "address of the agent proxy as host:port (falls back to INFISICAL_AGENT_PROXY_ADDRESS)")
	agentProxyConnectCmd.Flags().StringP("env", "e", "", "environment slug to fetch proxied services and secrets from (falls back to INFISICAL_ENVIRONMENT or .infisical.json)")
	agentProxyConnectCmd.Flags().String("path", "/", "secret path (folder) scope (falls back to INFISICAL_SECRET_PATH or defaultSecretPath in .infisical.json)")
	agentProxyConnectCmd.Flags().String("projectId", "", "project id (falls back to INFISICAL_PROJECT_ID or .infisical.json)")
	util.RegisterMachineIdentityAuthFlags(agentProxyConnectCmd, "agent")
	agentProxyConnectCmd.Flags().String("token", "", "machine identity access token to use instead of authenticating; takes precedence over --auth-method")
	agentProxyConnectCmd.Flags().String("no-proxy", "", "additional comma-separated hosts to bypass the proxy (always merged with localhost,127.0.0.1)")
	agentProxyConnectCmd.Flags().Bool("allow-readable-brokered-secrets", false, "start even if the agent can read secrets that proxied services broker to it (bypasses a misconfiguration guardrail; falls back to INFISICAL_AGENT_PROXY_ALLOW_READABLE_BROKERED_SECRETS)")

	agentProxyStartCmd.Flags().Int("port", 17322, "port for the agent proxy to listen on")
	agentProxyStartCmd.Flags().String("unmatched-host", "allow", "policy for hosts with no proxied service: allow | block")
	agentProxyStartCmd.Flags().Int("poll-interval", 60, "seconds between permission/credential refreshes for active agents")
	util.RegisterMachineIdentityAuthFlags(agentProxyStartCmd, "agent proxy")
	agentProxyStartCmd.Flags().String("token", "", "machine identity access token to use instead of authenticating; takes precedence over --auth-method, and the proxy cannot renew it")
	agentProxyStartCmd.Flags().String("log-format", "console", "log output format: console | json")
	agentProxyStartCmd.Flags().String("log-file", "", "also write json logs to this file (in addition to the console/json stream)")

	agentProxyCmd.AddCommand(agentProxyConnectCmd)
	agentProxyCmd.AddCommand(agentProxyStartCmd)
	secretsCmd.AddCommand(agentProxyCmd)
}
