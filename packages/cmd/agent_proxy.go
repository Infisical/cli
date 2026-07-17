package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var agentProxyCmd = &cobra.Command{
	Use:                   "agent-proxy",
	Short:                 "Secrets brokering: run an agent proxy and connect agents to it",
	DisableFlagsInUseLine: true,
}

var agentProxyConnectCmd = &cobra.Command{
	Use:                   "connect [flags] -- [agent start command]",
	Short:                 "Set up the environment and launch an agent behind the agent proxy",
	Example:               "infisical secrets agent-proxy connect --proxy=<proxy-host>:17322 --projectId=<project-id> --env=prod --path=/myapp -- claude",
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

// Stripped so the agent never sees the long-lived MI credentials, only the scoped short-lived JWT set below.
var credentialEnvKeys = []string{
	util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME,
	util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME,
	util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME,
}

var requiredNoProxy = []string{"localhost", "127.0.0.1"}

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
	proxyAddr, err := cmd.Flags().GetString("proxy")
	if err != nil || proxyAddr == "" {
		util.HandleError(fmt.Errorf("the --proxy flag is required (e.g. --proxy=<proxy-host>:17322)"))
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

	token := resolveAgentToken(cmd)

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

	allowReadableBrokered, _ := cmd.Flags().GetBool("allow-readable-brokered-secrets")
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

func resolveAgentToken(cmd *cobra.Command) *models.TokenDetails {
	clientID, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME}, "")
	clientSecret, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME}, "")

	if clientID != "" && clientSecret != "" {
		loginResp, err := util.UniversalAuthLogin(clientID, clientSecret)
		if err != nil {
			util.HandleError(err, "Failed to authenticate the agent machine identity")
		}
		return &models.TokenDetails{
			Type:  util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER,
			Token: loginResp.AccessToken,
		}
	}

	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to resolve authentication")
	}
	if token == nil {
		util.HandleError(fmt.Errorf("authentication required; provide --client-id/--client-secret, env vars, or a token"))
	}
	return token
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
	if token.Type == util.SERVICE_TOKEN_IDENTIFIER {
		params.InfisicalToken = token.Token
	} else if token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER {
		params.UniversalAuthAccessToken = token.Token
	}

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

	env["HTTPS_PROXY"] = proxy
	env["HTTP_PROXY"] = proxy
	env["NO_PROXY"] = mergeNoProxy(append(operatorNoProxy, extraNoProxy)...)
	env["NODE_USE_ENV_PROXY"] = "1"
	env["OPENCLAW_PROXY_URL"] = proxy

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

	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel)

	if err := proc.Start(); err != nil {
		return err
	}

	go func() {
		for sig := range sigChannel {
			_ = proc.Process.Signal(sig)
		}
	}()

	if err := proc.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(ws.ExitStatus())
			}
		}
		return err
	}
	return nil
}

func init() {
	agentProxyConnectCmd.Flags().String("proxy", "", "address of the agent proxy (host:port)")
	agentProxyConnectCmd.Flags().StringP("env", "e", "", "environment slug to fetch proxied services and secrets from")
	agentProxyConnectCmd.Flags().String("path", "/", "secret path (folder) scope")
	agentProxyConnectCmd.Flags().String("projectId", "", "project id (falls back to INFISICAL_PROJECT_ID or .infisical.json)")
	agentProxyConnectCmd.Flags().String("client-id", "", "universal auth client id for the agent machine identity")
	agentProxyConnectCmd.Flags().String("client-secret", "", "universal auth client secret for the agent machine identity")
	agentProxyConnectCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	agentProxyConnectCmd.Flags().String("no-proxy", "", "additional comma-separated hosts to bypass the proxy (always merged with localhost,127.0.0.1)")
	agentProxyConnectCmd.Flags().Bool("allow-readable-brokered-secrets", false, "start even if the agent can read secrets that proxied services broker to it (bypasses a misconfiguration guardrail)")

	agentProxyStartCmd.Flags().Int("port", 17322, "port for the agent proxy to listen on")
	agentProxyStartCmd.Flags().String("unmatched-host", "allow", "policy for hosts with no proxied service: allow | block")
	agentProxyStartCmd.Flags().Int("poll-interval", 60, "seconds between permission/credential refreshes for active agents")
	agentProxyStartCmd.Flags().String("client-id", "", "universal auth client id for the agent proxy machine identity")
	agentProxyStartCmd.Flags().String("client-secret", "", "universal auth client secret for the agent proxy machine identity")
	agentProxyStartCmd.Flags().Bool("activity-log", true, "write an activity record per brokered request")
	agentProxyStartCmd.Flags().String("activity-log-file", "", "file to append activity records to (default: stdout)")
	agentProxyStartCmd.Flags().String("activity-log-format", "", "pretty | json (default: pretty on a terminal, json otherwise)")
	agentProxyStartCmd.Flags().String("activity-log-filter", "all", "which decisions to log: all | brokered | errors")

	agentProxyCmd.AddCommand(agentProxyConnectCmd)
	agentProxyCmd.AddCommand(agentProxyStartCmd)
	secretsCmd.AddCommand(agentProxyCmd)
}
