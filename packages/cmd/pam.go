package cmd

import (
	"time"

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

func init() {
	pamAccessCmd.Flags().String("reason", "", "Reason for accessing the account (stored for audit purposes)")
	pamAccessCmd.Flags().String("duration", "1h", "Duration for access session (e.g., '1h', '30m', '2h30m')")
	pamAccessCmd.Flags().Int("port", 0, "Port for the local proxy server (0 for auto-assign)")
	pamAccessCmd.Flags().String("target", "", "Target host to connect to (for accounts that allow multiple hosts, e.g. Windows AD)")

	pamCmd.AddCommand(pamAccessCmd)
	RootCmd.AddCommand(pamCmd)
}
