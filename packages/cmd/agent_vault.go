package cmd

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Top-level, beside gateway / relay / pam, rather than under `secrets`. The existing
// `infisical secrets agent-proxy` tree is a different product and is untouched.
var avCmd = &cobra.Command{
	Use:   "av",
	Short: "Agent Vault commands",
	Long:  "Run agents that hold no credentials, with a proxy that attaches them at the network boundary",
}

var avProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run an Agent Vault proxy",
	Long: `Run an Agent Vault proxy.

The proxy decides per request whether a host is allowed and attaches the real credential on the way out,
so the agent never holds a secret.

Enroll once with the token shown when the proxy was created, then run it with no token to serve:

  infisical av proxy --enrollment-token avp_...
  infisical av proxy

Traffic policy - which hosts bypass interception, what happens to an unmatched host, and how often the
proxy refreshes - is set in Infisical and arrives on every poll, so it has no flags here.`,
	Example:               "infisical av proxy --enrollment-token avp_7k2mf...",
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
		}, enrollmentToken); err != nil {
			util.HandleError(err, "Agent Vault proxy failed")
		}
	},
}

func init() {
	avProxyCmd.Flags().String("enrollment-token", "",
		"one-time token from Infisical, used to enroll this proxy. Not needed once enrolled")
	avProxyCmd.Flags().String("data-dir", "",
		fmt.Sprintf("where to keep the certificate authority and proxy token (default: %s)", defaultDataDirHelp()))
	// Not 17322: that is the existing `secrets agent-proxy start` default, the old feature is not being
	// removed, and both are expected to run on one box.
	avProxyCmd.Flags().Int("port", agentvault.DefaultPort, "port to listen on; 0 binds any free port, which the startup line then reports")
	avProxyCmd.Flags().String("log-format", "console", "log output format: console | json")
	avProxyCmd.Flags().String("log-file", "", "path to also write logs to")

	avCmd.AddCommand(avProxyCmd)
	RootCmd.AddCommand(avCmd)
}

func defaultDataDirHelp() string {
	dir, err := agentvault.DefaultDataDir()
	if err != nil {
		return "~/.infisical/agent-vault"
	}
	return dir
}
