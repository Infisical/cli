package cmd

import (
	"fmt"
	"os"
	"strings"
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

var pamAgenticCmd = &cobra.Command{
	Use:                   "agentic",
	Short:                 "Run AI agents against PAM accounts",
	Long:                  "Run AI agents against PAM accounts through local proxies",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

// agenticAccessUsage is shown with every argument error, since the '--' separator is easy to get
// wrong and the usual cobra error doesn't show the shape of the command.
const agenticAccessUsage = "  infisical pam agentic access -- <agent command>"

var pamAgenticAccessCmd = &cobra.Command{
	Use:   "access -- <agent command>",
	Short: "Start local proxies for your PAM accounts and launch an AI agent against them",
	Long: `Start a local proxy for each PAM account you can launch, then launch an AI agent with
instructions describing how to reach them.

By default every account you have access to is included, and anything that can't be
proxied is listed with the reason. Narrow it with --account, which may be repeated. An
account named with --account that can't be launched is an error.

Each account gets a free port chosen by the OS and keeps it for the whole run, so
nothing else can take that port while the agent is working.

Sessions are created lazily: binding the ports costs nothing, and an account the agent
never connects to never opens a PAM session.

Per-account guidance for the agent comes from the account's description in Infisical.

Instructions are delivered in whatever format the agent understands, and their path is
always exported as INFISICAL_PAM_CONTEXT_FILE so custom agents can pick them up too.

Authenticates as the logged-in user by default, or as a machine identity when --token
or INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN is set.`,
	Example: `  infisical pam agentic access -- claude
  infisical pam agentic access --account prod/orders-db -- codex --model gpt-5
  infisical pam agentic access --account prod/orders-db --account prod/bastion --duration 30m -- claude
  infisical pam agentic access --reason "investigating INC-4021" -- claude`,
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

		accounts, err := cmd.Flags().GetStringArray("account")
		if err != nil {
			util.HandleError(err, "Unable to parse account flag")
		}

		reason, err := cmd.Flags().GetString("reason")
		if err != nil {
			util.HandleError(err, "Unable to parse reason flag")
		}

		durationStr, err := cmd.Flags().GetString("duration")
		if err != nil {
			util.HandleError(err, "Unable to parse duration flag")
		}
		duration, err := time.ParseDuration(durationStr)
		if err != nil {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid duration %q. Use formats like '1h', '30m', '2h30m'.", durationStr))
		}
		if duration <= 0 {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Duration %q must be positive.", durationStr))
		}

		accounts = splitAccountFlags(accounts)

		// Everything after '--' is the agent command, passed through untouched. Without a separator
		// the arguments are still taken as the command, but anything with flags of its own needs the
		// '--', or cobra would try to parse them here.
		childArgs := args
		if dash := cmd.ArgsLenAtDash(); dash >= 0 {
			childArgs = args[dash:]
		}

		if len(childArgs) == 0 {
			util.PrintErrorMessageAndExit("No agent command given. Pass one after '--', for example:\n" + agenticAccessUsage)
		}

		accessToken := resolveAgentAccessToken(cmd)

		exitCode, err := pamagent.Run(pamagent.Options{
			Accounts:      accounts,
			Duration:      duration,
			Reason:        reason,
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

// splitAccountFlags lets one --account carry a comma-separated list, so both
// '--account a/b --account c/d' and '--account a/b,c/d' work. Blank entries are dropped rather than
// sent on to be reported as a missing account.
func splitAccountFlags(values []string) []string {
	var accounts []string
	for _, value := range values {
		for _, account := range strings.Split(value, ",") {
			if account = strings.TrimSpace(account); account != "" {
				accounts = append(accounts, account)
			}
		}
	}
	return accounts
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

	pamAgenticAccessCmd.Flags().StringArray("account", nil, "Account to expose, as folder/account. Repeatable. Defaults to every account you can launch")
	pamAgenticAccessCmd.Flags().String("duration", "1h", "How long each PAM session may last (e.g. '1h', '30m', '2h30m')")
	pamAgenticAccessCmd.Flags().String("reason", "", "Reason for access, recorded for audit. Required by accounts whose policy demands one")
	pamAgenticAccessCmd.Flags().String("agent", "", "Override agent detection (claude, codex, gemini, generic)")
	pamAgenticAccessCmd.Flags().String("token", "", "Run as a machine identity using its access token")
	pamAgenticAccessCmd.Flags().String("log-file", "", "Where to write proxy logs while the agent runs")

	pamAgenticCmd.AddCommand(pamAgenticAccessCmd)

	pamCmd.AddCommand(pamAccessCmd)
	pamCmd.AddCommand(pamAgenticCmd)
	RootCmd.AddCommand(pamCmd)
}
