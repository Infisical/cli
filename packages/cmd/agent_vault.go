package cmd

import (
	"fmt"
	"runtime"

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

Enroll once with the token shown when the proxy was created, then run it with no token to serve:

  infisical agent-vault proxy --enrollment-token avp_...
  infisical agent-vault proxy

Traffic policy - whether an agent may reach any host or only the hosts in its access bundle, which hosts
are exceptions to that, and how often the proxy refreshes - is set in Infisical and arrives on every
poll, so it has no flags here. Every HTTPS host is intercepted either way; an exception is not blocked,
not un-intercepted.`,
	Example:               "infisical agent-vault proxy --enrollment-token avp_7k2mf...",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		enrollmentToken, err := util.GetCmdFlagOrEnvWithDefaultValue(
			cmd, "enrollment-token", []string{"INFISICAL_AGENT_VAULT_ENROLLMENT_TOKEN"}, "")
		if err != nil {
			util.HandleError(err, "Unable to read --enrollment-token")
		}

		dataDir, err := util.GetCmdFlagOrEnvWithDefaultValue(
			cmd, "data-dir", []string{"INFISICAL_AGENT_VAULT_DATA_DIR"}, "")
		if err != nil {
			util.HandleError(err, "Unable to read --data-dir")
		}

		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			util.HandleError(err, "Unable to read --port")
		}
		if port < 0 || port > 65535 {
			util.HandleError(fmt.Errorf("--port must be between 0 and 65535, got %d. 0 asks for any free port", port))
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

		if err := agentvault.Start(agentvault.Options{
			Port:    port,
			DataDir: dataDir,
			OnReady: func(enrolledNow bool) {
				Telemetry.CaptureEvent("cli-command:agent-vault proxy", posthog.NewProperties().
					Set("version", util.CLI_VERSION).
					Set("platform", runtime.GOOS).
					Set("enrolledNow", enrolledNow).
					Set("customPort", port != agentvault.DefaultPort).
					Set("customDataDir", dataDir != "").
					Set("logFormat", logFormat))
			},
		}, enrollmentToken); err != nil {
			util.HandleError(err, "Agent Vault proxy failed")
		}
	},
}

func init() {
	agentVaultProxyCmd.Flags().String("enrollment-token", "",
		"one-time token from Infisical, used to enroll this proxy. Not needed once enrolled")
	agentVaultProxyCmd.Flags().String("data-dir", "",
		fmt.Sprintf("where to keep the certificate authority and proxy token (default: %s)", defaultDataDirHelp()))
	agentVaultProxyCmd.Flags().Int("port", agentvault.DefaultPort, "port to listen on; 0 binds any free port, which the startup line then reports")
	agentVaultProxyCmd.Flags().String("log-format", "console", "log output format: console | json")
	agentVaultProxyCmd.Flags().String("log-file", "", "path to also write logs to")

	agentVaultCmd.AddCommand(agentVaultProxyCmd)
	RootCmd.AddCommand(agentVaultCmd)
}

func defaultDataDirHelp() string {
	dir, err := agentvault.DefaultDataDir()
	if err != nil {
		return "~/.infisical/agent-vault"
	}
	return dir
}
