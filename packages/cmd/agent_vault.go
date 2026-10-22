package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Top-level, beside gateway / relay / pam: the existing `infisical secrets agent-proxy` tree is a
// different product.
var agentVaultCmd = &cobra.Command{
	Use:     "agent-vault",
	Aliases: []string{"av"},
	Short:   "Agent Vault commands",
	Long:    "Run agents that hold no credentials, with a proxy that attaches them at the network boundary",
}

var agentVaultProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run an Agent Vault proxy",
	Long: `Run an Agent Vault proxy.

The proxy decides per request whether a host is allowed and attaches the real credential on the way out,
so the agent never holds a secret.

Start the proxy with the proxy token shown when it was created or its token was last rotated. You can run
it on as many machines as you need with one token: each loads its settings and certificate authority from
Infisical when it starts. On a shared host, pass the token in INFISICAL_AGENT_VAULT_PROXY_TOKEN rather than --proxy-token,
which other users can read from the process list:

  INFISICAL_AGENT_VAULT_PROXY_TOKEN=... infisical agent-vault proxy

After each start the proxy saves its settings and certificate authority under --data-dir, when that
directory is writable, and uses them only if Infisical can't be reached on a later start with the same
token.

Infisical issues the certificate authority the proxy serves. To serve your own instead, pass --ca-cert
and --ca-key, each as a PEM, the base64 of a PEM, or a file path.

A proxy's settings - its traffic policy, the exceptions to it, and how often it refreshes - are set in
Infisical and reach the proxy while it runs, so they have no flags here. Every HTTPS host is intercepted either way; an exception is not blocked,
not un-intercepted.`,
	Example:               "INFISICAL_AGENT_VAULT_PROXY_TOKEN=eyJhb... infisical agent-vault proxy",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		in, err := readAgentVaultProxyInputs(cmd)
		if err != nil {
			util.HandleError(err)
		}

		logFormat, err := cmd.Flags().GetString("log-format")
		if err != nil {
			util.HandleError(err, "Unable to read --log-format")
		}
		logFile, err := cmd.Flags().GetString("log-file")
		if err != nil {
			util.HandleError(err, "Unable to read --log-file")
		}

		writer, err := BuildAgentProxyLogWriter(logFormat, logFile)
		if err != nil {
			util.HandleError(err, "Unable to configure logging")
		}
		log.Logger = zerolog.New(writer).With().Timestamp().Logger()

		for _, warning := range in.warnings {
			log.Warn().Msg("agent-vault: " + warning)
		}

		opts := agentvault.Options{
			Port:    in.port,
			DataDir: in.dataDir,
			OwnCa:   in.ownCa,
			OnReady: func() {
				Telemetry.CaptureEvent("cli-command:agent-vault proxy", posthog.NewProperties().
					Set("version", util.CLI_VERSION).
					Set("platform", runtime.GOOS).
					Set("customPort", in.port != agentvault.DefaultPort).
					Set("customDataDir", in.dataDir != "").
					Set("ownCa", in.ownCa != nil).
					Set("logFormat", logFormat))
			},
		}

		if err := agentvault.Start(opts, in.proxyToken); err != nil {
			util.HandleError(err, "Agent Vault proxy failed")
		}
	},
}

type agentVaultProxyInputs struct {
	proxyToken string
	dataDir    string
	port       int
	ownCa      *agentvault.OwnCa
	warnings   []string
}

// Warnings are returned rather than logged because the logger is configured after this runs.
func readAgentVaultProxyInputs(cmd *cobra.Command) (agentVaultProxyInputs, error) {
	var in agentVaultProxyInputs
	var err error

	in.proxyToken, err = util.GetCmdFlagOrEnvWithDefaultValue(
		cmd, "proxy-token", []string{"INFISICAL_AGENT_VAULT_PROXY_TOKEN"}, "")
	if err != nil {
		return in, fmt.Errorf("unable to read --proxy-token: %w", err)
	}

	in.dataDir, err = util.GetCmdFlagOrEnvWithDefaultValue(
		cmd, "data-dir", []string{"INFISICAL_AGENT_VAULT_DATA_DIR"}, "")
	if err != nil {
		return in, fmt.Errorf("unable to read --data-dir: %w", err)
	}

	in.port, err = cmd.Flags().GetInt("port")
	if err != nil {
		return in, fmt.Errorf("unable to read --port: %w", err)
	}
	portSource := "--port"
	if raw := strings.TrimSpace(os.Getenv("INFISICAL_AGENT_VAULT_PORT")); raw != "" && !cmd.Flags().Changed("port") {
		portSource = "INFISICAL_AGENT_VAULT_PORT"
		in.port, err = strconv.Atoi(raw)
		if err != nil {
			return in, fmt.Errorf("INFISICAL_AGENT_VAULT_PORT must be a whole number, got %q", raw)
		}
	}
	if in.port < 0 || in.port > 65535 {
		return in, fmt.Errorf("%s must be between 0 and 65535, got %d. 0 asks for any free port", portSource, in.port)
	}

	caCert, caCertSource, err := agentVaultFlagOrEnv(cmd, "ca-cert", "INFISICAL_AGENT_VAULT_CA_CERT")
	if err != nil {
		return in, err
	}
	caKey, caKeySource, err := agentVaultFlagOrEnv(cmd, "ca-key", "INFISICAL_AGENT_VAULT_CA_KEY")
	if err != nil {
		return in, err
	}
	if (caCert == "") != (caKey == "") {
		return in, errors.New("--ca-cert and --ca-key go together")
	}
	if caCert != "" {
		// Only the key is a secret; the certificate is handed to every agent anyway.
		if caKeySource == "--ca-key" && strings.Contains(caKey, "-----BEGIN ") {
			in.warnings = append(in.warnings, "--ca-key is visible in the process list; prefer the env var INFISICAL_AGENT_VAULT_CA_KEY")
		}
		in.ownCa, err = agentvault.LoadOwnCa(agentvault.OwnCaInput{
			Cert: caCert, CertSource: caCertSource,
			Key: caKey, KeySource: caKeySource,
		})
		if err != nil {
			return in, err
		}
		in.warnings = append(in.warnings, in.ownCa.Warnings()...)
	}

	return in, nil
}

// The source is the flag's name or the env var's, whichever the value came from, so errors can point at it.
func agentVaultFlagOrEnv(cmd *cobra.Command, flag, env string) (value, source string, err error) {
	value, err = cmd.Flags().GetString(flag)
	if err != nil {
		return "", "", fmt.Errorf("unable to read --%s: %w", flag, err)
	}
	if value != "" {
		return value, "--" + flag, nil
	}
	return strings.TrimSpace(os.Getenv(env)), env, nil
}

func init() {
	addAgentVaultProxyFlags(agentVaultProxyCmd)

	agentVaultCmd.AddCommand(agentVaultProxyCmd)
	RootCmd.AddCommand(agentVaultCmd)
}

func addAgentVaultProxyFlags(cmd *cobra.Command) {
	cmd.Flags().String("proxy-token", "",
		"token from Infisical that starts this proxy; you can run it on as many machines as you need")
	cmd.Flags().String("data-dir", "",
		fmt.Sprintf("where the proxy saves its settings and certificate authority for starts while Infisical can't be reached (default: %s)", defaultDataDirHelp()))
	cmd.Flags().String("ca-cert", "", "your own certificate authority to serve, instead of the one Infisical issues: PEM, base64 PEM or file path")
	cmd.Flags().String("ca-key", "", "private key for --ca-cert: PEM, base64 PEM or file path")
	cmd.Flags().Int("port", agentvault.DefaultPort, "port to listen on; 0 binds any free port, which the startup line then reports")
	cmd.Flags().String("log-format", "console", "log output format: console | json")
	cmd.Flags().String("log-file", "", "path to also write logs to")
	// Units written for enrollment still pass this on every start; failing on an unknown flag would take an
	// enrolled proxy down on a CLI upgrade, so it is accepted and ignored. Remove after 2026-12-21.
	cmd.Flags().String("enrollment-token", "", "no longer used")
	_ = cmd.Flags().MarkHidden("enrollment-token")
	_ = cmd.Flags().MarkDeprecated("enrollment-token", "start the proxy with --proxy-token instead")
}

func defaultDataDirHelp() string {
	dir, err := agentvault.DefaultDataDir()
	if err != nil {
		return "~/.infisical/agent-vault"
	}
	return dir
}
