package cmd

import (
	"cmp"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// The server validates names as slugs; matching that here keeps a typo a one-line message instead of a raw
// 422 body, which is all the CLI can print for a schema rejection.
var agentVaultBundleNameRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

const agentVaultCaFileName = "ca.pem"

// Served by the proxy itself over plain HTTP, not by Infisical, so it uses a bare net/http client.
var agentVaultProxyHTTPClient = &http.Client{Timeout: 10 * time.Second}

type agentVaultProxyCa struct {
	ProxyID     string `json:"proxyId"`
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	Fingerprint string `json:"fingerprint"`
}

func fetchAgentVaultProxyCa(proxyAddr string) (agentVaultProxyCa, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/_agent-vault/ca", proxyAddr), nil)
	if err != nil {
		return agentVaultProxyCa{}, err
	}
	req.Header.Set("User-Agent", api.USER_AGENT)

	resp, err := agentVaultProxyHTTPClient.Do(req)
	if err != nil {
		return agentVaultProxyCa{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return agentVaultProxyCa{}, fmt.Errorf("the proxy answered %d to the certificate request", resp.StatusCode)
	}

	var ca agentVaultProxyCa
	if err := json.NewDecoder(resp.Body).Decode(&ca); err != nil {
		return agentVaultProxyCa{}, fmt.Errorf("the proxy's certificate response could not be read: %w", err)
	}
	return ca, nil
}

var avRunCmd = &cobra.Command{
	Use:   "run [flags] --proxy <host:port> -- [agent command]",
	Short: "Launch an agent that holds no credentials, routed through an Agent Vault proxy",
	Long: `Launch an agent that holds no credentials, routed through an Agent Vault proxy.

The agent's HTTP traffic is pointed at the proxy, which attaches the real credential at the network boundary.
The process you start receives a session token, the proxy address and the proxy's certificate authority, and
nothing else from Infisical.

Two ways to get a session, exactly one of them required:

  --access-bundle   mint one now over the named bundle (needs your login or a machine identity).
                    Revoked when the agent exits unless --keep-session is set.
  --session-token   run with a session token minted in the dashboard. Never revoked by this command.

The proxy's certificate authority is fetched from the proxy on every run and trusted for the agent. Pass
--ca-fingerprint to abort if the served certificate does not match a fingerprint from the Proxies page.

Unlike 'secrets agent-proxy run', this command does not sandbox the agent: it sets environment variables
and starts the process.`,
	Example: `  infisical av run --access-bundle on-call-infrastructure --proxy 10.0.1.5:17323 -- claude
  infisical av run --session-token agv_... --proxy 10.0.1.5:17323 --ca-fingerprint SHA256:9F:2C:... -- claude`,
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
	sessionToken, _ := cmd.Flags().GetString("session-token")
	if len(accessBundles) == 0 && sessionToken == "" {
		util.HandleError(fmt.Errorf("a session is required; pass --access-bundle <name> to mint one, or --session-token <session token> from the dashboard"))
	}
	if len(accessBundles) > 0 && sessionToken != "" {
		util.HandleError(fmt.Errorf("--access-bundle and --session-token are two ways to get one session; pass one of them, not both"))
	}
	if len(accessBundles) > 1 {
		util.HandleError(fmt.Errorf("a session carries one access bundle; pass --access-bundle once"))
	}
	for _, name := range accessBundles {
		if !agentVaultBundleNameRe.MatchString(name) {
			util.HandleError(fmt.Errorf("%q is not an access bundle name; names are lowercase letters, numbers and hyphens, for example 'coding-agent'", name))
		}
	}

	ttl, _ := cmd.Flags().GetString("ttl")

	// Neither flag can reach a session minted in the dashboard: its expiry was fixed when it was created.
	if sessionToken != "" {
		if cmd.Flags().Changed("ttl") {
			util.HandleError(fmt.Errorf(
				"--ttl applies to a session this command mints; the one behind --session-token was given its lifetime in the dashboard. Drop --ttl, or mint here with --access-bundle"))
		}
		if cmd.Flags().Changed("keep-session") {
			util.HandleError(fmt.Errorf(
				"--keep-session applies to a session this command mints; the one behind --session-token is never revoked here. Drop --keep-session, or mint here with --access-bundle"))
		}
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

	caResp, err := fetchAgentVaultProxyCa(proxyAddr)
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Unable to reach the Agent Vault proxy at %s. Check the address and that 'infisical av proxy' is running there", proxyAddr))
	}
	// Only the certificate the fingerprint was taken from is trusted from here on.
	caPEM, servedFingerprint, err := agentVaultCaFingerprint(caResp.Certificate)
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

		created, mintErr := api.CallCreateAgentVaultSession(httpClient, api.CreateAgentVaultSessionRequest{AccessBundles: accessBundles, TTL: ttl})
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
		if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
			util.HandleError(err, "Unable to write the certificate authority file")
		}
		caPath = caFile

		// Go binaries such as gh and docker ignore the CA environment variables and read the system trust store,
		// so macOS gets the keychain entry too.
		if runtime.GOOS == "darwin" && isatty.IsTerminal(os.Stdin.Fd()) {
			onPrompt := func() {
				util.PrintWarning("Adding the Agent Vault proxy's certificate authority to your login keychain, so tools that read the system trust store accept it. Approve the macOS prompt, or press Ctrl-C and re-run with --no-ca-trust to skip it.")
			}
			switch installed, terr := ensureAgentVaultCATrusted(caPath, onPrompt); {
			case errors.Is(terr, errAgentVaultTrustTimedOut):
				util.PrintWarning("The keychain prompt went unanswered, so the certificate authority was not added. The agent still runs, and tools that read the system trust store may report a certificate error. Re-run with --no-ca-trust to skip this step.")
			case terr != nil:
				util.PrintWarning(fmt.Sprintf("Unable to add the Agent Vault proxy CA to your login keychain (%v). Most tools will still work, but some may report a certificate error.", terr))
			case installed:
				util.PrintWarning("Added the Agent Vault proxy CA to your login keychain. This is one-time per proxy and persists for future runs.")
			}
		}
	}

	env := buildAgentVaultRunEnv(os.Environ(), proxyAddr, sessionToken, caPath, extraNoProxy)

	printAgentVaultRunSummary(proxyAddr, caResp, servedFingerprint, minted)

	exitCode := runAgentVaultChild(args, env)

	if minted != nil && !keepSession {
		// Never resolve the identity the usual way here: a long run would exit on the expiry check, or open the
		// login wizard on a terminal nobody is watching.
		httpClient, clientErr := util.GetRestyClientWithCustomHeaders()
		token, tokenErr := revocationToken(cmd)
		switch {
		case clientErr != nil || tokenErr != nil:
			util.PrintWarning(fmt.Sprintf(
				"The agent exited but its session could not be revoked (%v). Revoke it from the Sessions page.",
				cmp.Or(clientErr, tokenErr)))
		default:
			httpClient.SetAuthToken(token)
			if revokeErr := api.CallRevokeAgentVaultSession(httpClient, minted.ID); revokeErr != nil {
				util.PrintWarning(fmt.Sprintf("The agent exited but its session could not be revoked (%v). Revoke it from the Sessions page.", revokeErr))
			} else {
				fmt.Fprintln(os.Stderr, color.HiBlackString("session revoked"))
			}
		}
	}
	os.Exit(exitCode)
}

func revocationToken(cmd *cobra.Command) (string, error) {
	clientID, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-id", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME}, "")
	clientSecret, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "client-secret", []string{util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME}, "")
	if clientID != "" && clientSecret != "" {
		loginResp, err := util.UniversalAuthLogin(clientID, clientSecret)
		if err != nil {
			return "", err
		}
		return loginResp.AccessToken, nil
	}

	for _, name := range []string{util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, util.INFISICAL_TOKEN_NAME} {
		if token := os.Getenv(name); token != "" {
			return token, nil
		}
	}

	details, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil {
		return "", err
	}
	if !details.IsUserLoggedIn || details.LoginExpired || details.UserCredentials.JTWToken == "" {
		return "", errors.New("your Infisical login is no longer valid")
	}
	return details.UserCredentials.JTWToken, nil
}

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

// The parent's environment, with stale proxy settings replaced by ours and the CA-trust variables added.
// Nothing else is removed.
func buildAgentVaultRunEnv(parent []string, proxyAddr, sessionToken, caPath, extraNoProxy string) []string {
	stale := map[string]bool{}
	for _, k := range proxyEnvKeys {
		stale[k] = true
	}

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

// The token rides as the Proxy-Authorization username on every CONNECT, in the clear on the hop to the proxy.
func agentVaultProxyURL(proxyAddr, sessionToken string) string {
	u := url.URL{Scheme: "http", User: url.User(sessionToken), Host: proxyAddr}
	return u.String()
}

func agentVaultCaFingerprint(certificatePEM string) ([]byte, string, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", fmt.Errorf("the response did not contain a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, "", fmt.Errorf("the certificate could not be parsed: %w", err)
	}
	single := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	return single, agentvault.FingerprintOf(block.Bytes), nil
}

func agentVaultFingerprintsEqual(a, b string) bool {
	normalize := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(strings.ToUpper(s), "SHA256:")
		return strings.ReplaceAll(s, ":", "")
	}
	return normalize(a) != "" && normalize(a) == normalize(b)
}

func printAgentVaultRunSummary(proxyAddr string, ca agentVaultProxyCa, fingerprint string, minted *api.AgentVaultSession) {
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

}

// os.Exit here would skip the session revoke.
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

func init() {
	avRunCmd.Flags().StringArray("access-bundle", nil, "mint a session over the access bundle with this `name`")
	avRunCmd.Flags().String("session-token", "", "run with a session token minted in the dashboard instead of minting one")
	avRunCmd.Flags().String("ttl", "7d", "lifetime of a minted session, a duration such as 30m, 8h or 7d, or never")
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
