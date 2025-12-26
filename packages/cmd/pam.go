package cmd

import (
	"time"

	pam "github.com/Infisical/infisical-merge/packages/pam/local"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
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
	Use:                   "access-account <account-path>",
	Short:                 "Access PAM database accounts",
	Long:                  "Access PAM database accounts for Infisical. This starts a local database proxy server that you can use to connect to databases directly.",
	Example:               "infisical pam db access-account prod/db/my-postgres-account --duration 4h --port 5432 --project-id 1234567890",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		accountPath := args[0]

		projectID, err := cmd.Flags().GetString("project-id")
		if err != nil {
			util.HandleError(err, "Unable to parse project-id flag")
		}

		if projectID == "" {
			workspaceFile, err := util.GetWorkSpaceFromFile()
			if err != nil {
				util.PrintErrorMessageAndExit("Please either run infisical init to connect to a project or pass in project id with --project-id flag")
			}
			projectID = workspaceFile.WorkspaceId
		}

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

		pam.StartDatabaseLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, accountPath, projectID, durationStr, port)
	},
}

var pamSshCmd = &cobra.Command{
	Use:                   "ssh",
	Short:                 "SSH-related PAM commands",
	Long:                  "SSH-related PAM commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamSshAccessAccountCmd = &cobra.Command{
	Use:                   "access-account <account-path>",
	Short:                 "Start SSH session to PAM account",
	Long:                  "Start an SSH session to a PAM-managed SSH account. This command automatically launches an SSH client connected through the Infisical Gateway.",
	Example:               "infisical pam ssh access-account prod/ssh/my-ssh-account --duration 2h --project-id 1234567890",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		accountPath := args[0]

		durationStr, err := cmd.Flags().GetString("duration")
		if err != nil {
			util.HandleError(err, "Unable to parse duration flag")
		}

		// Parse duration
		_, err = time.ParseDuration(durationStr)
		if err != nil {
			util.HandleError(err, "Invalid duration format. Use formats like '1h', '30m', '2h30m'")
		}

		projectID, err := cmd.Flags().GetString("project-id")
		if err != nil {
			util.HandleError(err, "Unable to parse project-id flag")
		}

		if projectID == "" {
			workspaceFile, err := util.GetWorkSpaceFromFile()
			if err != nil {
				util.PrintErrorMessageAndExit("Please either run infisical init to connect to a project or pass in project id with --project-id flag")
			}
			projectID = workspaceFile.WorkspaceId
		}

		log.Debug().Msg("PAM SSH Access: Trying to fetch credentials using logged in details")

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		isConnected := util.ValidateInfisicalAPIConnection()

		if isConnected {
			log.Debug().Msg("PAM SSH Access: Connected to Infisical instance, checking logged in creds")
		}

		if err != nil {
			util.HandleError(err, "Unable to get logged in user details")
		}

		if isConnected && loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		pam.StartSSHLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, accountPath, projectID, durationStr)
	},
}
var pamKubernetesCmd = &cobra.Command{
	Use:                   "kubernetes",
	Aliases:               []string{"k8s"},
	Short:                 "Kubernetes-related PAM commands",
	Long:                  "Kubernetes-related PAM commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamKubernetesAccessAccountCmd = &cobra.Command{
	Use:                   "access-account <account-path>",
	Short:                 "Access Kubernetes PAM account",
	Long:                  "Access Kubernetes via a PAM-managed Kubernetes account. This command automatically launches a proxy connected to your Kubernetes cluster through the Infisical Gateway.",
	Example:               "infisical pam kubernetes access-account prod/ssh/my-k8s-account --duration 2h",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		accountPath := args[0]

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

		projectID, err := cmd.Flags().GetString("project-id")
		if err != nil {
			util.HandleError(err, "Unable to parse project-id flag")
		}

		if projectID == "" {
			workspaceFile, err := util.GetWorkSpaceFromFile()
			if err != nil {
				util.PrintErrorMessageAndExit("Please either run infisical init to connect to a project or pass in project id with --project-id flag")
			}
			projectID = workspaceFile.WorkspaceId
		}

		log.Debug().Msg("PAM Kubernetes Access: Trying to fetch credentials using logged in details")

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		isConnected := util.ValidateInfisicalAPIConnection()

		if isConnected {
			log.Debug().Msg("PAM Kubernetes Access: Connected to Infisical instance, checking logged in creds")
		}

		if err != nil {
			util.HandleError(err, "Unable to get logged in user details")
		}

		if isConnected && loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		pam.StartKubernetesLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, accountPath, projectID, durationStr, port)
	},
}

var pamRedisCmd = &cobra.Command{
	Use:                   "redis",
	Short:                 "Redis-related PAM commands",
	Long:                  "Redis-related PAM commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamRedisAccessAccountCmd = &cobra.Command{
	Use:                   "access-account <account-path>",
	Short:                 "Access Redis PAM account",
	Long:                  "Access Redis via a PAM-managed Redis account. This starts a local Redis proxy server that you can use to connect to Redis directly.",
	Example:               "infisical pam redis access-account prod/redis/my-redis-account --duration 4h --port 6379 --project-id 1234567890",
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		accountPath := args[0]

		projectID, err := cmd.Flags().GetString("project-id")
		if err != nil {
			util.HandleError(err, "Unable to parse project-id flag")
		}

		if projectID == "" {
			workspaceFile, err := util.GetWorkSpaceFromFile()
			if err != nil {
				util.PrintErrorMessageAndExit("Please either run infisical init to connect to a project or pass in project id with --project-id flag")
			}
			projectID = workspaceFile.WorkspaceId
		}

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

		log.Debug().Msg("PAM Redis Access: Trying to fetch secrets using logged in details")

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		isConnected := util.ValidateInfisicalAPIConnection()

		if isConnected {
			log.Debug().Msg("PAM Redis Access: Connected to Infisical instance, checking logged in creds")
		}

		if err != nil {
			util.HandleError(err, "Unable to get logged in user details")
		}

		if isConnected && loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		pam.StartRedisLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, accountPath, projectID, durationStr, port)
	},
}

func init() {
	pamDbCmd.AddCommand(pamDbAccessAccountCmd)
	pamDbAccessAccountCmd.Flags().String("duration", "1h", "Duration for database access session (e.g., '1h', '30m', '2h30m')")
	pamDbAccessAccountCmd.Flags().Int("port", 0, "Port for the local database proxy server (0 for auto-assign)")
	pamDbAccessAccountCmd.Flags().String("project-id", "", "Project ID of the account to access")

	pamSshCmd.AddCommand(pamSshAccessAccountCmd)
	pamSshAccessAccountCmd.Flags().String("duration", "1h", "Duration for SSH access session (e.g., '1h', '30m', '2h30m')")
	pamSshAccessAccountCmd.Flags().String("project-id", "", "Project ID of the account to access")

	pamKubernetesCmd.AddCommand(pamKubernetesAccessAccountCmd)
	pamKubernetesAccessAccountCmd.Flags().String("duration", "1h", "Duration for kubernetes access session (e.g., '1h', '30m', '2h30m')")
	pamKubernetesAccessAccountCmd.Flags().Int("port", 0, "Port for the local kubernetes proxy server (0 for auto-assign)")
	pamKubernetesAccessAccountCmd.Flags().String("project-id", "", "Project ID of the account to access")

	pamRedisCmd.AddCommand(pamRedisAccessAccountCmd)
	pamRedisAccessAccountCmd.Flags().String("duration", "1h", "Duration for Redis access session (e.g., '1h', '30m', '2h30m')")
	pamRedisAccessAccountCmd.Flags().Int("port", 0, "Port for the local Redis proxy server (0 for auto-assign)")
	pamRedisAccessAccountCmd.Flags().String("project-id", "", "Project ID of the account to access")

	pamCmd.AddCommand(pamDbCmd)
	pamCmd.AddCommand(pamSshCmd)
	pamCmd.AddCommand(pamKubernetesCmd)
	pamCmd.AddCommand(pamRedisCmd)
	rootCmd.AddCommand(pamCmd)
}
