package cmd

import (
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/Infisical/infisical-merge/packages/pam"
)

var pamCmd = &cobra.Command{
	Use:                   "pam",
	Short:                 "PAM-related commands",
	Long:                  "PAM-related commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamDbCmd = &cobra.Command{
	Use:                   "db",
	Short:                 "Database-related PAM commands",
	Long:                  "Database-related PAM commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamDbAccessAccountCmd = &cobra.Command{
	Use:                   "access-account <account-name-or-id>",
	Short:                 "Access PAM database accounts",
	Long:                  "Access PAM database accounts for Infisical. This starts a local database proxy server that you can use to connect to databases directly.",
	Example:               "infisical pam db access-account my-postgres-account --duration 4h --port 5432",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		accountID := args[0]

		durationStr, err := cmd.Flags().GetString("duration")
		if err != nil {
			util.HandleError(err, "Unable to parse duration flag")
		}

		// Parse duration
		_, err = time.ParseDuration(durationStr)
		if err != nil {
			util.HandleError(err, "Invalid duration format. Use formats like '1h', '30m', '2h30m'")
		}

		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			util.HandleError(err, "Unable to parse port flag")
		}

		log.Debug().Msg("PAM Database Access: Trying to fetch secrets using logged in details")

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		isConnected := util.ValidateInfisicalAPIConnection()

		if isConnected {
			log.Debug().Msg("PAM Database Access: Connected to Infisical instance, checking logged in creds")
		}

		if err != nil {
			util.HandleError(err, "Unable to get logged in user details")
		}

		if isConnected && loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		pam.StartDatabaseLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, accountID, durationStr, port)
	},
}

func init() {
	pamDbCmd.AddCommand(pamDbAccessAccountCmd)
	pamDbAccessAccountCmd.Flags().String("duration", "1h", "Duration for database access session (e.g., '1h', '30m', '2h30m')")
	pamDbAccessAccountCmd.Flags().Int("port", 0, "Port for the local database proxy server (0 for auto-assign)")

	pamCmd.AddCommand(pamDbCmd)
	rootCmd.AddCommand(pamCmd)
}
