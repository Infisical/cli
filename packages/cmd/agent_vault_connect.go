package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// Set by `agent-vault run` when it writes the proxy's CA for the agent, so a `connect` the agent starts can trust
// the proxy without asking Infisical.
const agentVaultCaFileEnv = "INFISICAL_AGENT_VAULT_CA_FILE"

const agentVaultFingerprintsTimeout = 15 * time.Second

var agentVaultConnectCmd = &cobra.Command{
	Use:   "connect [service...]",
	Short: "Open local ports to the database and SSH services in a session",
	Long: `Open local ports to the database and SSH services in an Agent Vault session.

Each service gets its own port on 127.0.0.1, and its address and an example command are printed once the port is
open. Connect your usual client (psql, mysql, ssh) there with any username and no password: each connection is
tunnelled to the Agent Vault proxy over TLS, and the proxy logs in with the service's account. The ports stay
open until you stop this command. With one service, --port picks its local port; otherwise the system picks free
ones. With --all, a service the proxy refuses is skipped and the reason printed.

The session token and proxy address are read from INFISICAL_AGENT_VAULT_SESSION_TOKEN and
INFISICAL_AGENT_VAULT_PROXY_ADDRESS, which 'agent-vault run' sets for the agent, or from the flags. When
--ca-fingerprint is passed, the proxy's certificate authority must match it, whatever else would trust it.
Otherwise the proxy is trusted from the CA file 'agent-vault run' wrote, else from the fingerprints Infisical
lists for the session's proxies.`,
	Example: `  infisical agent-vault connect analytics
  infisical agent-vault connect analytics --port 5432
  infisical agent-vault connect analytics bastion
  infisical agent-vault connect --all`,
	Args: func(cmd *cobra.Command, args []string) error {
		if all, _ := cmd.Flags().GetBool("all"); all {
			if len(args) > 0 {
				return fmt.Errorf("pass service names or --all, not both")
			}
			return nil
		}
		if len(args) == 0 {
			return fmt.Errorf("name at least one service, or pass --all to open every database and SSH service in the session")
		}
		return nil
	},
	Run: runAgentVaultConnect,
}

func runAgentVaultConnect(cmd *cobra.Command, args []string) {
	connectAll, _ := cmd.Flags().GetBool("all")
	port, _ := cmd.Flags().GetInt("port")
	if cmd.Flags().Changed("port") {
		if connectAll || len(args) != 1 {
			exitWithError(cmd, errAgentVaultConnectPortNeedsOneService())
		}
		if port < 1 || port > 65535 {
			exitWithError(cmd, errAgentVaultConnectInvalidPort(port))
		}
	}

	// Under `agent-vault run` SSL_CERT_FILE holds only the proxy's CA, which on Linux replaces the system roots and
	// would fail the direct call to Infisical. This command pins the proxy's CA itself, so it never needs that file.
	if caFile := os.Getenv(agentVaultCaFileEnv); caFile != "" && os.Getenv("SSL_CERT_FILE") == caFile {
		_ = os.Unsetenv("SSL_CERT_FILE")
	}

	if flagValue, _ := cmd.Flags().GetString("session-token"); cmd.Flags().Changed("session-token") && strings.TrimSpace(flagValue) == "" {
		exitWithError(cmd, errAgentVaultConnectEmptyFlag("--session-token", agentVaultSessionTokenEnv))
	}
	sessionToken, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "session-token", []string{agentVaultSessionTokenEnv}, "")
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		exitWithError(cmd, errAgentVaultConnectSessionTokenRequired())
	}

	if flagValue, _ := cmd.Flags().GetString("proxy"); cmd.Flags().Changed("proxy") && strings.TrimSpace(flagValue) == "" {
		exitWithError(cmd, errAgentVaultConnectEmptyFlag("--proxy", agentVaultProxyAddressEnv))
	}
	proxyAddr, _ := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "proxy", []string{agentVaultProxyAddressEnv}, "")
	proxyAddr = trimProxyScheme(strings.TrimSpace(proxyAddr))
	if proxyAddr == "" {
		exitWithError(cmd, errAgentVaultConnectProxyRequired())
	}
	proxySource := "--proxy"
	if !cmd.Flags().Changed("proxy") {
		proxySource = agentVaultProxyAddressEnv
	}
	if err := validateProxyAddrFrom(proxyAddr, proxySource); err != nil {
		exitWithError(cmd, &util.CLIError{Code: errCodeInvalidFlagValue, Message: err.Error() + "."})
	}

	pinnedFingerprint, _ := cmd.Flags().GetString("ca-fingerprint")
	if cmd.Flags().Changed("ca-fingerprint") && strings.TrimSpace(pinnedFingerprint) == "" {
		exitWithError(cmd, errAgentVaultConnectEmptyFlag("--ca-fingerprint", ""))
	}

	roots, trustSource, err := trustAgentVaultProxy(proxyAddr, sessionToken, pinnedFingerprint)
	if err != nil {
		exitWithError(cmd, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := &agentvault.ConnectClient{ProxyAddr: proxyAddr, SessionToken: sessionToken, RootCAs: roots}
	available, err := client.ListNativeServices(ctx)
	if err != nil {
		exitWithError(cmd, classifyAgentVaultConnectError(err, proxyAddr))
	}
	services, err := pickAgentVaultConnectServices(available, args, connectAll)
	if err != nil {
		exitWithError(cmd, err)
	}

	// Every service is checked before any port opens, so a refusal is this command's error, not a failed login later.
	// Named services are all or nothing; --all opens what it can, since one broken service shouldn't take the rest.
	var refused []error
	open := services[:0:0]
	for _, service := range services {
		err := client.Probe(ctx, service.Name)
		if err == nil {
			open = append(open, service)
			continue
		}
		classified := classifyAgentVaultConnectError(err, proxyAddr)
		if !connectAll || !isAgentVaultServiceRefusal(err) {
			exitWithError(cmd, classified)
		}
		warnAgentVaultConnect(service.Name, classified.Error())
		refused = append(refused, classified)
	}
	if len(open) == 0 {
		if len(refused) == 1 {
			exitWithError(cmd, refused[0])
		}
		exitWithError(cmd, errAgentVaultConnectAllRefused())
	}
	services = open

	listeners := make([]net.Listener, len(services))
	for i, service := range services {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			exitWithError(cmd, errAgentVaultConnectLocalPort(service.Name, port, err))
		}
		listeners[i] = ln
	}

	blocks := make([]string, len(services))
	for i, service := range services {
		blocks[i] = agentVaultConnectBlock(service, listeners[i].Addr().(*net.TCPAddr).Port)
	}
	fmt.Print(strings.Join(blocks, "\n"))
	if silent, _ := cmd.Flags().GetBool("silent"); !silent {
		fmt.Fprintln(os.Stderr, "\nUse any username and no password: the proxy logs in with each service's account. Press Ctrl+C to close the ports.")
	}

	Telemetry.CaptureEventAsync("cli-command:agent-vault connect", posthog.NewProperties().
		Set("version", util.CLI_VERSION).
		Set("platform", runtime.GOOS).
		Set("all", connectAll).
		Set("services", len(services)).
		Set("refused", len(refused)).
		Set("serviceTypes", agentVaultConnectServiceTypes(services)).
		Set("customPort", port != 0).
		Set("trust", trustSource))

	done := make(chan struct{}, len(services))
	for i, service := range services {
		go func() {
			defer func() { done <- struct{}{} }()
			onError := func(err error) {
				var local *agentvault.LocalConnError
				if errors.As(err, &local) {
					warnAgentVaultConnect(service.Name, fmt.Sprintf("a local connection failed: %s", local.Err))
					return
				}
				warnAgentVaultConnect(service.Name, classifyAgentVaultConnectError(err, proxyAddr).Error())
			}
			_ = client.ServeLocal(ctx, listeners[i], service, onError)
		}()
	}
	for range services {
		<-done
	}
}

// A refusal of one service, which --all can skip. One that ends the session or comes from a proxy that can't
// reach Infisical would refuse every other service too.
func isAgentVaultServiceRefusal(err error) bool {
	var refused *agentvault.ProxyRefusedError
	return errors.As(err, &refused) && refused.Status == http.StatusForbidden && !refused.SessionInvalid()
}

// A warning that doesn't end the command. The message can carry the proxy's free-form refusal text, so it gets the
// same cleaning as the errors exitWithError prints.
func warnAgentVaultConnect(name, msg string) {
	fmt.Fprintf(util.GetStderrWriter(), "%s: %s\n", util.SanitizeDisplay(name), util.RedactCredentials(util.SanitizeDisplay(msg)))
}

func agentVaultConnectServiceTypes(services []agentvault.NativeServiceInfo) []string {
	seen := map[string]bool{}
	var types []string
	for _, service := range services {
		if !seen[service.Type] {
			seen[service.Type] = true
			types = append(types, service.Type)
		}
	}
	sort.Strings(types)
	return types
}

func pickAgentVaultConnectServices(available []agentvault.NativeServiceInfo, names []string, all bool) ([]agentvault.NativeServiceInfo, error) {
	if len(available) == 0 {
		return nil, errAgentVaultConnectNoServices()
	}
	if all {
		return available, nil
	}
	var picked []agentvault.NativeServiceInfo
	seen := map[string]bool{}
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		if seen[key] {
			continue
		}
		seen[key] = true
		found := false
		for _, service := range available {
			if strings.EqualFold(service.Name, key) {
				picked = append(picked, service)
				found = true
				break
			}
		}
		if !found {
			return nil, errAgentVaultConnectServiceNotFound(name, available)
		}
	}
	return picked, nil
}

var agentVaultConnectTypeLabels = map[string]string{"postgres": "PostgreSQL", "mysql": "MySQL", "ssh": "SSH"}

// The database is left out of the examples: the proxy connects to the service's own database whatever the client
// asks for, and a name pasted into a shell command could run something else. Postgres turns TLS off on the local
// hop, which the proxy refuses anyway, so an inherited PGSSLMODE=require can't fail the login.
func agentVaultConnectBlock(service agentvault.NativeServiceInfo, port int) string {
	title := service.Name
	if label, ok := agentVaultConnectTypeLabels[service.Type]; ok {
		title += " (" + label + ")"
	}
	block := fmt.Sprintf("%s\n  Address:  127.0.0.1:%d\n", title, port)
	if example := agentVaultConnectExample(service.Type, port); example != "" {
		block += fmt.Sprintf("  Example:  %s\n", example)
	}
	return block
}

func agentVaultConnectExample(serviceType string, port int) string {
	switch serviceType {
	case "postgres":
		return fmt.Sprintf(`psql "postgres://agent@127.0.0.1:%d/?sslmode=disable"`, port)
	case "mysql":
		return fmt.Sprintf("mysql -h 127.0.0.1 -P %d -u agent", port)
	case "ssh":
		// The proxy presents a new host key on every connection, and the hop is local, so the key isn't checked.
		return fmt.Sprintf("ssh -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null agent@127.0.0.1", port)
	}
	return ""
}

const (
	agentVaultTrustPinned    = "pinned"
	agentVaultTrustRunCa     = "run-ca-file"
	agentVaultTrustInfisical = "infisical"
)

// trustAgentVaultProxy returns the pool holding only the proxy's CA and what vouched for it, or refuses. It never
// falls back to an unpinned connection: whoever can block Infisical must not be able to make `connect` trust
// whatever answers at the address.
func trustAgentVaultProxy(proxyAddr, sessionToken, pinnedFingerprint string) (*x509.CertPool, string, error) {
	caResp, err := fetchAgentVaultProxyCa(proxyAddr)
	if err != nil {
		return nil, "", errAgentVaultConnectProxyUnreachable(proxyAddr, err)
	}
	servedPEM, served, err := agentVaultCaFingerprint(caResp.Certificate)
	if err != nil {
		return nil, "", errAgentVaultConnectProxyUntrusted(proxyAddr, err)
	}

	source := ""
	switch {
	// A pin always has the last word: it can make up for Infisical being out of reach, but never be overruled.
	case pinnedFingerprint != "":
		if !agentVaultFingerprintsEqual(pinnedFingerprint, served) {
			return nil, "", errAgentVaultConnectFingerprintMismatch(proxyAddr, served)
		}
		source = agentVaultTrustPinned
	default:
		if fingerprints, ok := agentVaultRunCaFingerprints(); ok && containsAgentVaultFingerprint(fingerprints, served) {
			source = agentVaultTrustRunCa
			break
		}
		fingerprints, err := fetchAgentVaultSessionProxyCaFingerprints(sessionToken)
		if err != nil {
			return nil, "", classifyAgentVaultFingerprintsError(err, proxyAddr)
		}
		if !containsAgentVaultFingerprint(fingerprints, served) {
			return nil, "", errAgentVaultConnectProxyUntrusted(proxyAddr, nil)
		}
		source = agentVaultTrustInfisical
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(servedPEM) {
		return nil, "", errAgentVaultConnectProxyUntrusted(proxyAddr, errors.New("the proxy's certificate authority could not be loaded"))
	}
	return pool, source, nil
}

func classifyAgentVaultFingerprintsError(err error, proxyAddr string) *util.CLIError {
	var apiErr *api.APIError
	switch {
	case errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden):
		return errAgentVaultConnectSessionInvalid(err)
	case isInfisicalRouteMissing(err):
		return errAgentVaultConnectFingerprintsNotListed(proxyAddr, err)
	case !errors.As(err, &apiErr):
		return errAgentVaultConnectInfisicalUnreachable(proxyAddr, strings.TrimSuffix(config.INFISICAL_URL, "/api"), err)
	}
	return errAgentVaultConnectProxyUntrusted(proxyAddr, err)
}

// The fingerprints of the certificates in the CA file `agent-vault run` wrote, when this runs under it.
func agentVaultRunCaFingerprints() ([]string, bool) {
	path := strings.TrimSpace(os.Getenv(agentVaultCaFileEnv))
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, false
	}
	var fingerprints []string
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			fingerprints = append(fingerprints, agentvault.FingerprintOf(block.Bytes))
		}
	}
	return fingerprints, len(fingerprints) > 0
}

// Asks Infisical directly, never through the Agent Vault proxy: under `agent-vault run` HTTPS_PROXY points at the
// proxy, whose policy may refuse Infisical, and the answer must not come from the thing it vouches for.
// TODO: revisit when Agent Vault has a service discovery endpoint, which could return these with the services.
func fetchAgentVaultSessionProxyCaFingerprints(sessionToken string) ([]string, error) {
	useAgentVaultSessionTokenDomain()
	client, err := newAgentVaultSkillsHTTPClient()
	if err != nil {
		return nil, err
	}
	client.RemoveProxy()
	ctx, cancel := context.WithTimeout(context.Background(), agentVaultFingerprintsTimeout)
	defer cancel()
	res, err := api.CallGetAgentVaultSessionProxyCaFingerprints(ctx, client, sessionToken)
	if err != nil {
		return nil, err
	}
	return res.Fingerprints, nil
}

func containsAgentVaultFingerprint(fingerprints []string, fingerprint string) bool {
	for _, candidate := range fingerprints {
		if agentVaultFingerprintsEqual(candidate, fingerprint) {
			return true
		}
	}
	return false
}

func init() {
	agentVaultConnectCmd.Flags().String("session-token", "", "the session token, or set "+agentVaultSessionTokenEnv)
	agentVaultConnectCmd.Flags().String("proxy", "", "the proxy's host:port, or set "+agentVaultProxyAddressEnv)
	agentVaultConnectCmd.Flags().String("ca-fingerprint", "", "trust the proxy only if its certificate authority has this SHA256 fingerprint, shown in the Certificate Authority column on the Proxies page in Infisical")
	agentVaultConnectCmd.Flags().Bool("all", false, "open a port for every database and SSH service in the session, skipping any the proxy refuses")
	agentVaultConnectCmd.Flags().Int("port", 0, "the local port to open, when connecting to one service (default: a free port)")
	agentVaultCmd.AddCommand(agentVaultConnectCmd)
}
