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

var pamAccessCmd = &cobra.Command{
	Use:                   "access <account-id>",
	Short:                 "Access PAM accounts",
	Long:                  "Access PAM accounts for Infisical. This starts a local proxy server that you can use to access PAM accounts directly.",
	Example:               "infisical pam access f55e5610-0c3c-42e0-bccf-fc526f68a990 --duration 4h --port 8080",
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

		log.Debug().Msg("PAM Access: Trying to fetch secrets using logged in details")

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		isConnected := util.ValidateInfisicalAPIConnection()

		if isConnected {
			log.Debug().Msg("PAM Access: Connected to Infisical instance, checking logged in creds")
		}

		if err != nil {
			util.HandleError(err, "Unable to get logged in user details")
		}

		if isConnected && loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		pam.StartLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, accountID, durationStr, port)
	},
}

func init() {
	pamCmd.AddCommand(pamAccessCmd)
	pamAccessCmd.Flags().String("duration", "1h", "Duration for PAM access session (e.g., '1h', '30m', '2h30m')")
	pamAccessCmd.Flags().Int("port", 0, "Port for the local proxy server (0 for auto-assign)")
	rootCmd.AddCommand(pamCmd)
}
