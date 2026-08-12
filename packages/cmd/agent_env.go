package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// secretsAgentCmd is the parent for everything an agent needs: today that is `agent gateway`.
var secretsAgentCmd = &cobra.Command{
	Use:                   "agent",
	Short:                 "Run agents with their credentials brokered by Infisical",
	DisableFlagsInUseLine: true,
}

const mitmCaRelativePath = ".infisical/agent-gateways/broker-ca.pem"

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

// Addresses of host IPC endpoints. Not secret values, but handing them to the agent points it at sockets it
// can use: the SSH/GPG agents as a signing oracle, and the session bus, where systemd --user
// StartTransientUnit runs a process outside the sandbox. Unix sockets are not namespaced, so on Linux
// dropping these is what keeps them out of reach. Scrubbed by default; --pass-env re-admits a specific one.
var authAgentEnvKeys = []string{
	"SSH_AUTH_SOCK",
	"SSH_AGENT_PID",
	"GPG_AGENT_INFO",
	"DBUS_SESSION_BUS_ADDRESS",
	"DBUS_SYSTEM_BUS_ADDRESS",
	"XDG_RUNTIME_DIR",
}

var requiredNoProxy = []string{"localhost", "127.0.0.1"}

// setProxyEnv points the child's HTTP clients at the broker. Both letter cases are set on purpose: curl
// honours only the lowercase http_proxy for plain-HTTP URLs, so an uppercase-only environment sends those
// requests to DNS instead of the broker. Shared by connect and run so the two cannot drift.
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

// Only the executable name: argv past the first word routinely carries credentials.
func telemetryAgentName(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return filepath.Base(args[0])
}

// writeBrokerCa persists the trust anchor the agent's HTTP clients must accept, under a directory the
// sandbox denies the agent, so it cannot be swapped for one the agent generated.
func writeBrokerCa(certificatePem string) (string, error) {
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

func runAgentProcess(args, env []string) error {
	log.Info().Msg(color.GreenString("Starting agent with its requests brokered by Infisical"))

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
	secretsCmd.AddCommand(secretsAgentCmd)
}
