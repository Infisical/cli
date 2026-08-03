package cmd

import (
	"os"
	"time"

	pamagent "github.com/Infisical/infisical-merge/packages/pam/agent"
	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

var pamCmd = &cobra.Command{
	Use:                   "pam",
	Short:                 "PAM-related commands",
	Long:                  "PAM-related commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamAccessCmd = &cobra.Command{
	Use:   "access <path>",
	Short: "Launch a PAM session for the account at the given path",
	Long: `Launch a PAM session for the account at the given path.
The path format is: /folder/account-name (leading slash optional)`,
	Example:               "infisical pam access /production/postgres-main --duration 2h",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		path := args[0]

		reason, err := cmd.Flags().GetString("reason")
		if err != nil {
			util.HandleError(err, "Unable to parse reason flag")
		}

		durationStr, err := cmd.Flags().GetString("duration")
		if err != nil {
			util.HandleError(err, "Unable to parse duration flag")
		}

		_, err = time.ParseDuration(durationStr)
		if err != nil {
			util.HandleError(err, "Invalid duration format. Use formats like '1h', '30m', '2h30m'")
		}

		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			util.HandleError(err, "Unable to parse port flag")
		}

		targetHost, err := cmd.Flags().GetString("target")
		if err != nil {
			util.HandleError(err, "Unable to parse target flag")
		}

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		if err != nil {
			util.HandleError(err, "Unable to get logged in user details")
		}

		isConnected := util.ValidateInfisicalAPIConnection()
		if isConnected && loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		pam.StartPAMAccess(loggedInUserDetails.UserCredentials.JTWToken, path, reason, durationStr, targetHost, port)
	},
}

var pamAgentCmd = &cobra.Command{
	Use:                   "agent",
	Short:                 "Run AI agents against PAM accounts",
	Long:                  "Run AI agents against PAM accounts through local proxies",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

// agentConnectUsage is shown with every argument error, since the '--' separator and the manifest
// argument are easy to get wrong and the usual cobra error doesn't show the shape of the command.
const agentConnectUsage = "  infisical pam agent connect <manifest.yaml> -- <agent command>"

var pamAgentConnectCmd = &cobra.Command{
	Use:   "connect <manifest> -- <agent command>",
	Short: "Start local proxies from a manifest and launch an AI agent against them",
	Long: `Start a local proxy for each PAM account listed in a manifest file, then launch an AI
agent with instructions describing how to reach them.

Sessions are created lazily: binding the ports costs nothing, and an account the agent
never connects to never opens a PAM session.

The manifest path comes first, then the agent command after a '--' separator. Each
manifest account takes an 'account' path and a 'port', plus optional 'duration',
'reason', 'agent_instructions', and 'target_host' for accounts that front more than one
host, such as a Windows AD account covering a domain.

Instructions are delivered in whatever format the agent understands, and their path is
always exported as INFISICAL_PAM_CONTEXT_FILE so custom agents can pick them up too.

Authenticates as the logged-in user by default, or as a machine identity when --token
or INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN is set.`,
	Example: `  infisical pam agent connect manifest.yaml -- claude
  infisical pam agent connect manifest.yaml -- codex --model gpt-5`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		agentOverride, err := cmd.Flags().GetString("agent")
		if err != nil {
			util.HandleError(err, "Unable to parse agent flag")
		}

		logFile, err := cmd.Flags().GetString("log-file")
		if err != nil {
			util.HandleError(err, "Unable to parse log-file flag")
		}

		// The manifest is the leading argument and everything after '--' is the agent command,
		// passed through untouched. Without a separator the first argument is still the manifest,
		// so a plain 'connect manifest.yaml claude' works; anything taking flags of its own needs
		// the '--', or cobra would try to parse them here.
		manifestArgs, childArgs := args, []string(nil)
		if dash := cmd.ArgsLenAtDash(); dash >= 0 {
			manifestArgs, childArgs = args[:dash], args[dash:]
		} else if len(args) > 0 {
			manifestArgs, childArgs = args[:1], args[1:]
		}

		if len(manifestArgs) == 0 {
			util.PrintErrorMessageAndExit("No manifest given. Pass the path to one first, for example:\n" + agentConnectUsage)
		}
		if len(manifestArgs) > 1 {
			util.PrintErrorMessageAndExit("Expected a single manifest path before '--', for example:\n" + agentConnectUsage)
		}
		if len(childArgs) == 0 {
			util.PrintErrorMessageAndExit("No agent command given. Pass one after '--', for example:\n" + agentConnectUsage)
		}

		accessToken := resolveAgentAccessToken(cmd)

		exitCode, err := pamagent.Run(pamagent.Options{
			ManifestPath:  manifestArgs[0],
			Argv:          childArgs,
			AgentOverride: agentOverride,
			LogFile:       logFile,
			AccessToken:   accessToken,
		})
		if err != nil {
			util.PrintErrorMessageAndExit(err.Error())
		}

		if exitCode != 0 {
			os.Exit(exitCode)
		}
	},
}

// resolveAgentAccessToken returns the token to authenticate with. A machine identity access token
// takes precedence when one is supplied, since an unattended agent shouldn't depend on a human's
// browser login session staying alive. Otherwise we fall back to the stored user login.
func resolveAgentAccessToken(cmd *cobra.Command) string {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse token")
	}

	if token != nil {
		if token.Type == util.SERVICE_TOKEN_IDENTIFIER {
			util.PrintErrorMessageAndExit("PAM does not support service tokens. Use a machine identity access token, or log in as a user.")
		}
		return token.Token
	}

	util.RequireLogin()

	loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil {
		util.HandleError(err, "Unable to get logged in user details")
	}

	if util.ValidateInfisicalAPIConnection() && loggedInUserDetails.LoginExpired {
		loggedInUserDetails = util.EstablishUserLoginSession()
	}

	return loggedInUserDetails.UserCredentials.JTWToken
}

func init() {
	pamAccessCmd.Flags().String("reason", "", "Reason for accessing the account (stored for audit purposes)")
	pamAccessCmd.Flags().String("duration", "1h", "Duration for access session (e.g., '1h', '30m', '2h30m')")
	pamAccessCmd.Flags().Int("port", 0, "Port for the local proxy server (0 for auto-assign)")
	pamAccessCmd.Flags().String("target", "", "Target host to connect to (for accounts that allow multiple hosts, e.g. Windows AD)")

	pamAgentConnectCmd.Flags().String("agent", "", "Override agent detection (claude, codex, gemini, generic)")
	pamAgentConnectCmd.Flags().String("token", "", "Run as a machine identity using its access token")
	pamAgentConnectCmd.Flags().String("log-file", "", "Where to write proxy logs while the agent runs")

	pamAgentCmd.AddCommand(pamAgentConnectCmd)

	pamCmd.AddCommand(pamAccessCmd)
	pamCmd.AddCommand(pamAgentCmd)
	RootCmd.AddCommand(pamCmd)
}
