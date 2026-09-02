package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var agentVaultSessionTTLs = []string{"1h", "8h", "24h", "7d", "never"}

const agentVaultCaFileName = "ca.pem"

var avRunCmd = &cobra.Command{
	Use:   "run [flags] --proxy <host:port> -- [agent command]",
	Short: "Launch an agent that holds no credentials, routed through an Agent Vault proxy",
	Long: `Launch an agent that holds no credentials, routed through an Agent Vault proxy.

The agent's HTTP traffic is pointed at the proxy, which attaches the real credential at the network boundary.
The process you start receives a session token, the proxy address and the proxy's certificate authority, and
nothing else from Infisical.

Two ways to get a session, exactly one of them required:

  --access-bundle   mint one now over the named bundles (repeatable; needs your login or a machine identity).
                    Revoked when the agent exits unless --keep-session is set.
  --token           run with a session token minted in the dashboard. Never revoked by this command.

The proxy's certificate authority is fetched from the proxy on every run and trusted for the agent. Pass
--ca-fingerprint to abort if the served certificate does not match a fingerprint from the Proxies page.

Unlike 'secrets agent-proxy run', this command does not sandbox the agent: it sets environment variables
and starts the process.`,
	Example: `  infisical av run --access-bundle on-call-infrastructure --proxy 10.0.1.5:17323 -- claude
  infisical av run --token agv_... --proxy 10.0.1.5:17323 --ca-fingerprint SHA256:9F:2C:... -- claude`,
	DisableFlagsInUseLine: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("provide the agent command to run after '--', e.g. -- claude")
		}
		return nil
	},
	Run: runAgentVaultRun,
}

func runAgentVaultRun(cmd *cobra.Command, args []string) {
	accessBundles, _ := cmd.Flags().GetStringArray("access-bundle")
	sessionToken, _ := cmd.Flags().GetString("token")
	if len(accessBundles) == 0 && sessionToken == "" {
		util.HandleError(fmt.Errorf("a session is required; pass --access-bundle <name> to mint one, or --token <session token> from the dashboard"))
	}
	if len(accessBundles) > 0 && sessionToken != "" {
		util.HandleError(fmt.Errorf("--access-bundle and --token are two ways to get one session; pass one of them, not both"))
	}

	ttl, _ := cmd.Flags().GetString("ttl")
	if !containsString(agentVaultSessionTTLs, ttl) {
		util.HandleError(fmt.Errorf("--ttl must be one of %s, got %q", strings.Join(agentVaultSessionTTLs, ", "), ttl))
	}

	proxyAddr, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "proxy", []string{"INFISICAL_AGENT_VAULT_PROXY_ADDRESS"}, "")
	if err != nil {
		util.HandleError(err, "Unable to read --proxy")
	}
	if proxyAddr == "" {
		util.HandleError(fmt.Errorf("the proxy address is required; pass --proxy <host:port> or set INFISICAL_AGENT_VAULT_PROXY_ADDRESS. The same proxy has a different address from every network, so there is no name to look it up by"))
	}
	proxyAddr = strings.TrimPrefix(strings.TrimPrefix(proxyAddr, "http://"), "https://")

	pinnedFingerprint, _ := cmd.Flags().GetString("ca-fingerprint")
	noCaTrust, _ := cmd.Flags().GetBool("no-ca-trust")
	keepSession, _ := cmd.Flags().GetBool("keep-session")
	extraNoProxy, _ := cmd.Flags().GetString("no-proxy")

	caFile, _ := cmd.Flags().GetString("ca-file")
	if caFile == "" {
		dataDir, dirErr := agentvault.DefaultDataDir()
		if dirErr != nil {
			util.HandleError(dirErr, "Unable to resolve the default data directory; pass --ca-file")
		}
		caFile = filepath.Join(dataDir, agentVaultCaFileName)
	}

	// Plain HTTP to the proxy's own address, so the client is deliberately not the authenticated one.
	proxyClient := resty.New().SetTimeout(10 * time.Second)
	caResp, err := api.CallGetAgentVaultProxyCa(proxyClient, proxyAddr)
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Unable to reach the Agent Vault proxy at %s. Check the address and that 'infisical av proxy' is running there", proxyAddr))
	}
	servedFingerprint, err := agentVaultCaFingerprint(caResp.Certificate)
	if err != nil {
		util.HandleError(err, "The proxy served a certificate authority that could not be read")
	}
	if pinnedFingerprint != "" && !agentVaultFingerprintsEqual(pinnedFingerprint, servedFingerprint) {
		util.HandleError(fmt.Errorf("the proxy at %s serves a certificate authority with fingerprint %s, not the pinned %s. Nothing was written and the agent was not started. If the proxy was re-enrolled, take the new fingerprint from the Proxies page; otherwise something else is answering at that address", proxyAddr, servedFingerprint, pinnedFingerprint))
	}

	var minted *api.AgentVaultSession
	if len(accessBundles) > 0 {
		identity := resolveAgentVaultIdentityToken(cmd)
		httpClient, clientErr := util.GetRestyClientWithCustomHeaders()
		if clientErr != nil {
			util.HandleError(clientErr, "Failed to build the API client")
		}
		httpClient.SetAuthToken(identity)

		bundles, listErr := api.CallListAgentVaultAccessBundles(httpClient)
		if listErr != nil {
			util.HandleError(listErr, "Unable to list your Agent Vault access bundles")
		}
		ids, resolveErr := resolveAgentVaultBundleIDs(accessBundles, bundles.AccessBundles)
		if resolveErr != nil {
			util.HandleError(resolveErr)
		}

		created, mintErr := api.CallCreateAgentVaultSession(httpClient, api.CreateAgentVaultSessionRequest{AccessBundleIDs: ids, TTL: ttl})
		if mintErr != nil {
			util.HandleError(mintErr, "Unable to mint an Agent Vault session")
		}
		minted = &created.Session
		sessionToken = created.Session.Token

		Telemetry.SetActor(telemetry.IdentityClaimsFromToken(identity))
	}

	Telemetry.CaptureEvent("cli-command:av run", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("agent", telemetryAgentName(args)).
		Set("platform", runtime.GOOS).
		Set("sessionSource", map[bool]string{true: "access-bundle", false: "token"}[minted != nil]).
		Set("ttl", ttl).
		Set("keepSession", keepSession).
		Set("pinned", pinnedFingerprint != "").
		Set("caTrust", !noCaTrust))

	caPath := ""
	if !noCaTrust {
		if err := os.MkdirAll(filepath.Dir(caFile), 0o700); err != nil {
			util.HandleError(err, "Unable to create the directory for the certificate authority file")
		}
		if err := os.WriteFile(caFile, []byte(caResp.Certificate), 0o600); err != nil {
			util.HandleError(err, "Unable to write the certificate authority file")
		}
		caPath = caFile

		// Go binaries such as gh and docker ignore the CA environment variables and read the system trust
		// store, so macOS gets the keychain entry too. Declining is fine: everything else still works.
		if runtime.GOOS == "darwin" {
			switch installed, terr := ensureCATrusted(caPath); {
			case terr != nil:
				util.PrintWarning(fmt.Sprintf("Unable to add the Agent Vault proxy CA to your login keychain (%v). Most tools will still work, but some may report a certificate error.", terr))
			case installed:
				util.PrintWarning("Added the Agent Vault proxy CA to your login keychain. This is one-time per proxy and persists for future runs.")
			}
		}
	}

	env := buildAgentVaultRunEnv(os.Environ(), proxyAddr, sessionToken, caPath, extraNoProxy)

	printAgentVaultRunSummary(proxyClient, proxyAddr, caResp, servedFingerprint, sessionToken, minted)

	exitCode := runAgentVaultChild(args, env)

	if minted != nil && !keepSession {
		httpClient, clientErr := util.GetRestyClientWithCustomHeaders()
		if clientErr == nil {
			httpClient.SetAuthToken(resolveAgentVaultIdentityToken(cmd))
			if revokeErr := api.CallRevokeAgentVaultSession(httpClient, minted.ID); revokeErr != nil {
				util.PrintWarning(fmt.Sprintf("The agent exited but its session could not be revoked (%v). Revoke it from the Sessions page.", revokeErr))
			} else {
				fmt.Fprintln(os.Stderr, color.HiBlackString("session revoked"))
			}
		}
	}
	os.Exit(exitCode)
}

// The identity that mints: --client-id/--client-secret (or their env vars) for a machine identity, else an
// access token in the environment, else the keyring login. --token is the session token here, so it is
// deliberately not read as an identity.
func resolveAgentVaultIdentityToken(cmd *cobra.Command) string {
	clientID, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME}, "")
	clientSecret, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME}, "")
	if clientID != "" && clientSecret != "" {
		loginResp, err := util.UniversalAuthLogin(clientID, clientSecret)
		if err != nil {
			util.HandleError(err, "Failed to authenticate the machine identity")
		}
		return loginResp.AccessToken
	}

	for _, name := range []string{util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, util.INFISICAL_TOKEN_NAME} {
		if token := os.Getenv(name); token != "" {
			failIfTokenExpired(token, fmt.Sprintf("the %s token", name))
			return token
		}
	}

	details, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil || !details.IsUserLoggedIn || details.LoginExpired {
		details = util.EstablishUserLoginSession()
	}
	if details.UserCredentials.JTWToken == "" {
		util.HandleError(fmt.Errorf("could not resolve your Infisical login; run 'infisical login', set %s, or pass --client-id and --client-secret", util.INFISICAL_TOKEN_NAME))
	}
	failIfTokenExpired(details.UserCredentials.JTWToken, "your login")
	return details.UserCredentials.JTWToken
}

// Names to ids, in the order given: order is the session's priority order, so it is preserved. An unknown
// name is an error that names it rather than a session silently missing a bundle.
func resolveAgentVaultBundleIDs(names []string, bundles []api.AgentVaultAccessBundle) ([]string, error) {
	byName := make(map[string]string, len(bundles))
	for _, b := range bundles {
		byName[b.Name] = b.ID
	}
	ids := make([]string, 0, len(names))
	var unknown []string
	for _, name := range names {
		if id, ok := byName[name]; ok {
			ids = append(ids, id)
			continue
		}
		unknown = append(unknown, name)
	}
	if len(unknown) > 0 {
		known := make([]string, 0, len(bundles))
		for _, b := range bundles {
			known = append(known, b.Name)
		}
		hint := "you have no access bundles; ask an Agent Vault admin to grant you one"
		if len(known) > 0 {
			hint = "the bundles you can reach are: " + strings.Join(known, ", ")
		}
		return nil, fmt.Errorf("no access bundle named %s is granted to you; %s", quoteAll(unknown), hint)
	}
	return ids, nil
}

// The child's environment: the proxy and CA-trust variables, stale proxy settings and Infisical credentials
// stripped, and nothing from Infisical beyond the session token inside the proxy URL.
func buildAgentVaultRunEnv(parent []string, proxyAddr, sessionToken, caPath, extraNoProxy string) []string {
	stale := map[string]bool{}
	for _, k := range proxyEnvKeys {
		stale[k] = true
	}
	for _, k := range credentialEnvKeys {
		stale[k] = true
	}
	stale[util.INFISICAL_TOKEN_NAME] = true

	var operatorNoProxy []string
	env := map[string]string{}
	for _, kv := range parent {
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

	setProxyEnv(env, agentVaultProxyURL(proxyAddr, sessionToken), mergeNoProxy(append(operatorNoProxy, extraNoProxy)...))

	if caPath != "" {
		for _, k := range caTrustEnvVars {
			env[k] = caPath
		}
	}

	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// http://<session token>@host:port. The token rides as the Proxy-Authorization username on every CONNECT,
// in the clear on the hop to the proxy, which is the accepted trade for a proxy inside your own network.
func agentVaultProxyURL(proxyAddr, sessionToken string) string {
	u := url.URL{Scheme: "http", User: url.User(sessionToken), Host: proxyAddr}
	return u.String()
}

func agentVaultCaFingerprint(certificatePEM string) (string, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		return "", fmt.Errorf("the response did not contain a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("the certificate could not be parsed: %w", err)
	}
	return agentvault.FingerprintOf(block.Bytes), nil
}

// Tolerates the ways a fingerprint gets copied around: with or without the SHA256: prefix, colons and case.
func agentVaultFingerprintsEqual(a, b string) bool {
	normalize := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(strings.ToUpper(s), "SHA256:")
		return strings.ReplaceAll(s, ":", "")
	}
	return normalize(a) != "" && normalize(a) == normalize(b)
}

func printAgentVaultRunSummary(proxyClient *resty.Client, proxyAddr string, ca api.AgentVaultProxyCaResponse, fingerprint, sessionToken string, minted *api.AgentVaultSession) {
	dim := color.HiBlackString
	fmt.Fprintln(os.Stderr, color.GreenString("Starting agent behind Agent Vault proxy %q at %s", ca.Name, proxyAddr))
	fmt.Fprintln(os.Stderr, dim("proxy CA fingerprint: "+fingerprint))
	if minted != nil {
		expiry := "never"
		if minted.ExpiresAt != nil {
			expiry = *minted.ExpiresAt
		}
		fmt.Fprintln(os.Stderr, dim("session expires: "+expiry))
	}

	// Best effort: the proxy answers what this session can reach right now. Never a credential value.
	who, err := api.CallAgentVaultWhoami(proxyClient, proxyAddr, sessionToken)
	if err != nil {
		log.Debug().Err(err).Msg("could not read the session's reachable hosts from the proxy")
		return
	}
	if len(who.Reachable) == 0 {
		util.PrintWarning("This session reaches no hosts: every access bundle it carries has been removed or emptied.")
		return
	}
	for _, r := range who.Reachable {
		fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("reachable: %s (%s, %s)", strings.Join(r.Hosts, ", "), r.AccessBundle, r.Credential)))
	}
}

// Starts the agent, forwards termination signals and returns its exit code, so the caller can revoke the
// session afterwards. os.Exit inside here would skip that.
func runAgentVaultChild(args, env []string) int {
	// #nosec G204 -- the command is provided directly by the operator running the CLI
	proc := exec.Command(args[0], args[1:]...)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	proc.Env = env

	if err := proc.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start the agent process: %v\n", err)
		return 1
	}

	stopForwarding := sandbox.ForwardTerminationSignals(proc)
	err := proc.Wait()
	stopForwarding()
	if err == nil {
		return 0
	}
	code, ok := sandbox.WaitExitCode(err)
	if !ok {
		fmt.Fprintf(os.Stderr, "agent process error: %v\n", err)
	}
	return code
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func quoteAll(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, fmt.Sprintf("%q", v))
	}
	return strings.Join(quoted, ", ")
}

func init() {
	avRunCmd.Flags().StringArray("access-bundle", nil, "mint a session over this access bundle (repeatable; order is priority order when two bundles cover one host)")
	avRunCmd.Flags().String("token", "", "run with a session token minted in the dashboard instead of minting one")
	avRunCmd.Flags().String("ttl", "7d", "lifetime of a minted session: 1h | 8h | 24h | 7d | never")
	avRunCmd.Flags().Bool("keep-session", false, "leave a minted session active when the agent exits")
	avRunCmd.Flags().String("proxy", "", "address of the Agent Vault proxy as host:port (falls back to INFISICAL_AGENT_VAULT_PROXY_ADDRESS)")
	avRunCmd.Flags().String("ca-fingerprint", "", "abort unless the proxy's certificate authority matches this SHA256 fingerprint from the Proxies page")
	avRunCmd.Flags().String("no-proxy", "", "additional comma-separated hosts to bypass the proxy (always merged with localhost,127.0.0.1)")
	avRunCmd.Flags().String("ca-file", "", "where to write the certificate authority fetched from the proxy; an output path, not a CA to trust (default: "+filepath.Join(defaultDataDirHelp(), agentVaultCaFileName)+")")
	avRunCmd.Flags().Bool("no-ca-trust", false, "skip writing the certificate authority and setting the trust variables, for a host that already trusts this proxy's CA (a pinned fingerprint is still checked)")
	avRunCmd.Flags().String("client-id", "", "universal auth client id of the machine identity that mints the session (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	avRunCmd.Flags().String("client-secret", "", "universal auth client secret of that machine identity (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")

	avCmd.AddCommand(avRunCmd)
}
