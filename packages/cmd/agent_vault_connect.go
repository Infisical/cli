package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
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

Each service gets its own port on 127.0.0.1, and a ready-to-run command is printed for it. Connect your usual
client (psql, mysql, ssh) there: each connection is tunnelled to the Agent Vault proxy over TLS, and the proxy
logs in with the service's account, so no password is needed. The ports stay open until you stop this command.

The session token and proxy address are read from INFISICAL_AGENT_VAULT_SESSION_TOKEN and
INFISICAL_AGENT_VAULT_PROXY_ADDRESS, which 'agent-vault run' sets for the agent, or from the flags. The proxy's
certificate authority is trusted from the file 'agent-vault run' wrote, else from the fingerprints Infisical lists
for the session's proxies, else from --ca-fingerprint.`,
	Example: `  infisical agent-vault connect analytics
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
	if err := validateProxyAddr(proxyAddr); err != nil {
		exitWithError(cmd, &util.CLIError{Code: errCodeInvalidFlagValue, Message: err.Error() + "."})
	}

	pinnedFingerprint, _ := cmd.Flags().GetString("ca-fingerprint")
	if cmd.Flags().Changed("ca-fingerprint") && strings.TrimSpace(pinnedFingerprint) == "" {
		exitWithError(cmd, errAgentVaultConnectEmptyFlag("--ca-fingerprint", ""))
	}

	roots, err := trustAgentVaultProxy(proxyAddr, sessionToken, pinnedFingerprint)
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
	for _, service := range services {
		if err := client.Probe(ctx, service.Name); err != nil {
			exitWithError(cmd, classifyAgentVaultConnectError(err, proxyAddr))
		}
	}

	listeners := make([]net.Listener, len(services))
	for i, service := range services {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			util.HandleError(err, fmt.Sprintf("Unable to open a local port for %s", service.Name))
		}
		listeners[i] = ln
	}

	width := 0
	for _, service := range services {
		width = max(width, len(service.Name))
	}
	for i, service := range services {
		port := listeners[i].Addr().(*net.TCPAddr).Port
		fmt.Printf("%-*s  %s\n", width, service.Name, agentVaultConnectCommand(service, port))
	}
	fmt.Fprintln(os.Stderr, "\nUse any username and don't pass a password: the proxy logs in with each service's account. Press Ctrl+C to close the ports.")

	done := make(chan struct{}, len(services))
	for i, service := range services {
		go func() {
			defer func() { done <- struct{}{} }()
			onError := func(err error) {
				fmt.Fprintf(os.Stderr, "%s: %s\n", service.Name, classifyAgentVaultConnectError(err, proxyAddr).Error())
			}
			_ = client.ServeLocal(ctx, listeners[i], service, onError)
		}()
	}
	for range services {
		<-done
	}
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

// The same commands PAM's local access prints. Postgres turns TLS off on the local hop, which the proxy refuses
// anyway, so an inherited PGSSLMODE=require can't fail the login.
func agentVaultConnectCommand(service agentvault.NativeServiceInfo, port int) string {
	switch service.Type {
	case "postgres":
		return fmt.Sprintf(`psql "postgres://agent@127.0.0.1:%d/%s?sslmode=disable"`, port, service.Database)
	case "mysql":
		return fmt.Sprintf("mysql -h 127.0.0.1 -P %d -u agent %s", port, service.Database)
	case "ssh":
		// The proxy presents a new host key on every connection, and the hop is local, so the key isn't checked.
		return fmt.Sprintf("ssh -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null agent@127.0.0.1", port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// trustAgentVaultProxy returns the pool holding only the proxy's CA, or refuses. It never falls back to an unpinned
// connection: whoever can block Infisical must not be able to make `connect` trust whatever answers at the address.
func trustAgentVaultProxy(proxyAddr, sessionToken, pinnedFingerprint string) (*x509.CertPool, error) {
	caResp, err := fetchAgentVaultProxyCa(proxyAddr)
	if err != nil {
		return nil, errAgentVaultConnectProxyUnreachable(proxyAddr, err)
	}
	servedPEM, served, err := agentVaultCaFingerprint(caResp.Certificate)
	if err != nil {
		return nil, errAgentVaultConnectProxyUntrusted(proxyAddr, err)
	}

	trusted := false
	if fingerprints, ok := agentVaultRunCaFingerprints(); ok && containsAgentVaultFingerprint(fingerprints, served) {
		trusted = true
	}
	if !trusted {
		fingerprints, err := fetchAgentVaultSessionProxyCaFingerprints(sessionToken)
		trusted = err == nil && containsAgentVaultFingerprint(fingerprints, served)
	}
	if pinnedFingerprint != "" {
		// A pin always has the last word: it can make up for Infisical being out of reach, but never be overruled.
		if !agentVaultFingerprintsEqual(pinnedFingerprint, served) {
			return nil, errAgentVaultConnectFingerprintMismatch(proxyAddr, served)
		}
		trusted = true
	}
	if !trusted {
		return nil, errAgentVaultConnectProxyUntrusted(proxyAddr, nil)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(servedPEM) {
		return nil, errAgentVaultConnectProxyUntrusted(proxyAddr, errors.New("the proxy's certificate authority could not be loaded"))
	}
	return pool, nil
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
	agentVaultConnectCmd.Flags().String("ca-fingerprint", "", "trust the proxy only if its certificate authority has this SHA256 fingerprint, shown on the proxy's page in Infisical")
	agentVaultConnectCmd.Flags().Bool("all", false, "open a port for every database and SSH service in the session")
	agentVaultCmd.AddCommand(agentVaultConnectCmd)
}
