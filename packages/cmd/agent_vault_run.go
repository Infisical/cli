package cmd

import (
	"cmp"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/mattn/go-isatty"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// The server validates names as slugs; matching that here keeps a typo a one-line message instead of a raw
// 422 body, which is all the CLI can print for a schema rejection.
var agentVaultBundleNameRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// One file per proxy, so a run against a second proxy cannot overwrite the certificate an agent that is
// already running still trusts through its environment. The ID comes from the proxy over unauthenticated
// HTTP, so it is checked as a UUID before it can shape a path.
func agentVaultCaFilePath(dataDir, proxyID string) (string, error) {
	if _, err := uuid.Parse(proxyID); err != nil {
		return "", fmt.Errorf("the proxy reported an invalid proxy ID %q; something other than an Agent Vault proxy may be answering at that address", proxyID)
	}
	return filepath.Join(dataDir, "ca-"+proxyID+".pem"), nil
}

// Served by the proxy itself over plain HTTP, not by Infisical, so it uses its own net/http client.
// Proxy is nil rather than absent: the default transport would route this through the operator's
// HTTP_PROXY, and the address names a machine on their own network, so it never belongs to a proxy.
var agentVaultProxyHTTPClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{Proxy: nil},
}

// The endpoint is unauthenticated plain HTTP, so whatever answers at that address is bounded before
// it is read. A certificate and three short fields are a couple of kilobytes.
const agentVaultCaResponseLimit = 1 << 20

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
	if err := json.NewDecoder(io.LimitReader(resp.Body, agentVaultCaResponseLimit)).Decode(&ca); err != nil {
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
inherits the rest of your environment unchanged.

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

// nonBlank drops values that name nothing, so a stray empty --access-bundle does not count towards
// the one-bundle limit.
func nonBlank(values []string) []string {
	var kept []string
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			kept = append(kept, value)
		}
	}
	return kept
}

func runAgentVaultRun(cmd *cobra.Command, args []string) {
	accessBundles, _ := cmd.Flags().GetStringArray("access-bundle")
	sessionToken, _ := cmd.Flags().GetString("session-token")

	// Whether the flag was given has to come from the flag set: pflag discards a lone empty value, so
	// --access-bundle "" parses to an empty slice and is otherwise indistinguishable from the flag never
	// appearing. Blanks alongside a real name are dropped here too, or the count below would report two
	// bundles to someone who named one. Same shape as PAM's --account.
	accessBundles = nonBlank(accessBundles)
	if cmd.Flags().Changed("access-bundle") && len(accessBundles) == 0 {
		util.HandleError(fmt.Errorf("--access-bundle was given but names no bundle; pass a name like 'coding-agent'"))
	}
	if cmd.Flags().Changed("session-token") && strings.TrimSpace(sessionToken) == "" {
		util.HandleError(fmt.Errorf("--session-token was given but is empty; pass a session token from the dashboard"))
	}

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
	// Trimmed here as well as in the env lookup, so a flag holding only spaces gets the message below
	// rather than a parse error about a space in the host name.
	proxyAddr = strings.TrimSpace(proxyAddr)
	if proxyAddr == "" {
		util.HandleError(fmt.Errorf("the proxy address is required; pass --proxy <host:port> or set INFISICAL_AGENT_VAULT_PROXY_ADDRESS. The same proxy has a different address from every network, so there is no name to look it up by"))
	}
	proxyAddr = trimProxyScheme(proxyAddr)
	if err := validateProxyAddr(proxyAddr); err != nil {
		util.HandleError(err)
	}

	pinnedFingerprint, _ := cmd.Flags().GetString("ca-fingerprint")
	noCaTrust, _ := cmd.Flags().GetBool("no-ca-trust")
	keepSession, _ := cmd.Flags().GetBool("keep-session")
	extraNoProxy, _ := cmd.Flags().GetString("no-proxy")

	caResp, err := fetchAgentVaultProxyCa(proxyAddr)
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Unable to reach the Agent Vault proxy at %s. Check the address and that 'infisical av proxy' is running there", proxyAddr))
	}

	caFile, _ := cmd.Flags().GetString("ca-file")
	if caFile == "" {
		dataDir, dirErr := agentvault.DefaultDataDir()
		if dirErr != nil {
			util.HandleError(dirErr, "Unable to resolve the default data directory; pass --ca-file")
		}
		caFile, err = agentVaultCaFilePath(dataDir, caResp.ProxyID)
		if err != nil {
			util.HandleError(err)
		}
	}
	// The path goes into the agent's environment, and the agent resolves it against its own working directory.
	caFile, err = filepath.Abs(caFile)
	if err != nil {
		util.HandleError(err, "Unable to resolve --ca-file to an absolute path")
	}
	// Only the certificate the fingerprint was taken from is trusted from here on.
	caPEM, servedFingerprint, err := agentVaultCaFingerprint(caResp.Certificate)
	if err != nil {
		util.HandleError(err, "The proxy served a certificate authority that could not be read")
	}
	if pinnedFingerprint != "" && !agentVaultFingerprintsEqual(pinnedFingerprint, servedFingerprint) {
		util.HandleError(fmt.Errorf("the proxy at %s serves a certificate authority with fingerprint %s, not the pinned %s. Nothing was written and the agent was not started. If the proxy was re-enrolled, take the new fingerprint from the Proxies page; otherwise something else is answering at that address", proxyAddr, servedFingerprint, pinnedFingerprint))
	}

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

	// Minted last, once every file is written and the keychain prompt has been answered: from here to the
	// child starting nothing may exit, or the session outlives the command with no message naming it.
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

// url.Parse is no use here: the documented input is a bare host:port, which it either rejects outright
// or reads as a scheme with an empty host. A scheme is accepted anyway because people paste one.
// The address goes into the agent's proxy URL with the session token as the password, so anything that is
// not a bare host and port reaches the agent as a malformed URL, and curl prints that URL, token included.
func validateProxyAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || strings.ContainsAny(host, " \t/?#@") {
		return fmt.Errorf("--proxy must be host:port, such as 10.0.1.5:17323, got %q", addr)
	}
	if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("--proxy must name a port between 1 and 65535, got %q", addr)
	}
	return nil
}

func trimProxyScheme(addr string) string {
	for _, scheme := range []string{"http://", "https://"} {
		if len(addr) >= len(scheme) && strings.EqualFold(addr[:len(scheme)], scheme) {
			return addr[len(scheme):]
		}
	}
	return addr
}

// Both halves have to be filled or undici, urllib, requests and libcurl send no credentials at all and
// every CONNECT comes back 407, while git refuses to start and asks for a password. The token is the
// password half because tools mask that one and print the username; git names it verbatim in its errors.
func agentVaultProxyURL(proxyAddr, sessionToken string) string {
	u := url.URL{Scheme: "http", User: url.UserPassword(agentvault.ProxyAuthUsername, sessionToken), Host: proxyAddr}
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
	avRunCmd.Flags().String("ttl", "7d", "lifetime of the session this command creates: one number and one unit, such as 30m, 8h or 7d (not 2h30m), or never")
	avRunCmd.Flags().Bool("keep-session", false, "leave a minted session active when the agent exits")
	avRunCmd.Flags().String("proxy", "", "address of the Agent Vault proxy as host:port (falls back to INFISICAL_AGENT_VAULT_PROXY_ADDRESS)")
	avRunCmd.Flags().String("ca-fingerprint", "", "abort unless the proxy's certificate authority matches this SHA256 fingerprint from the Proxies page")
	avRunCmd.Flags().String("no-proxy", "", "additional comma-separated hosts to bypass the proxy (always merged with localhost,127.0.0.1)")
	avRunCmd.Flags().String("ca-file", "", "where to write the certificate authority fetched from the proxy; an output path, not a CA to trust (default: "+filepath.Join(defaultDataDirHelp(), "ca-<proxy-id>.pem")+")")
	avRunCmd.Flags().Bool("no-ca-trust", false, "skip writing the certificate authority and setting the trust variables, for a host that already trusts this proxy's CA (a pinned fingerprint is still checked)")
	avRunCmd.Flags().String("client-id", "", "universal auth client id of the machine identity that mints the session (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_ID)")
	avRunCmd.Flags().String("client-secret", "", "universal auth client secret of that machine identity (falls back to INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)")

	avCmd.AddCommand(avRunCmd)
}
