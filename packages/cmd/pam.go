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

// ==================== Database Commands ====================

var pamDbCmd = &cobra.Command{
	Use:                   "db",
	Short:                 "Database-related PAM commands",
	Long:                  "Database-related PAM commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamDbAccessCmd = &cobra.Command{
	Use:                   "access",
	Short:                 "Access PAM database accounts",
	Long:                  "Access PAM database accounts for Infisical. This starts a local database proxy server that you can use to connect to databases directly.",
	Example:               "infisical pam db access --resource infisical-shared-cloud-instances --account infisical --project-id b38bef10-2685-43c4-9a2c-635206d60bec --duration 4h",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		resourceName, _ := cmd.Flags().GetString("resource")
		accountName, _ := cmd.Flags().GetString("account")

		if resourceName == "" || accountName == "" {
			util.PrintErrorMessageAndExit("Both --resource and --account flags are required")
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

		pam.StartDatabaseLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, pam.PAMAccessParams{
			ResourceName: resourceName,
			AccountName:  accountName,
		}, projectID, durationStr, port)
	},
}

// ==================== SSH Commands ====================

var pamSshCmd = &cobra.Command{
	Use:                   "ssh",
	Short:                 "SSH-related PAM commands",
	Long:                  "SSH-related PAM commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamSshAccessCmd = &cobra.Command{
	Use:                   "access",
	Short:                 "Start SSH session to PAM account",
	Long:                  "Start an SSH session to a PAM-managed SSH account. This command automatically launches an SSH client connected through the Infisical Gateway.",
	Example:               "infisical pam ssh access --resource prod-servers --account root --project-id b38bef10-2685-43c4-9a2c-635206d60bec --duration 1h",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		resourceName, _ := cmd.Flags().GetString("resource")
		accountName, _ := cmd.Flags().GetString("account")

		if resourceName == "" || accountName == "" {
			util.PrintErrorMessageAndExit("Both --resource and --account flags are required")
		}

		durationStr, err := cmd.Flags().GetString("duration")
		if err != nil {
			util.HandleError(err, "Unable to parse duration flag")
		}

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

		pam.StartSSHLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, pam.PAMAccessParams{
			ResourceName: resourceName,
			AccountName:  accountName,
		}, projectID, durationStr)
	},
}

// ==================== Kubernetes Commands ====================

var pamKubernetesCmd = &cobra.Command{
	Use:                   "kubernetes",
	Aliases:               []string{"k8s"},
	Short:                 "Kubernetes-related PAM commands",
	Long:                  "Kubernetes-related PAM commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamKubernetesAccessCmd = &cobra.Command{
	Use:                   "access",
	Short:                 "Access Kubernetes PAM account",
	Long:                  "Access Kubernetes via a PAM-managed Kubernetes account. This command automatically launches a proxy connected to your Kubernetes cluster through the Infisical Gateway.",
	Example:               "infisical pam kubernetes access --resource prod-cluster --account developer --project-id b38bef10-2685-43c4-9a2c-635206d60bec --duration 4h",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		resourceName, _ := cmd.Flags().GetString("resource")
		accountName, _ := cmd.Flags().GetString("account")

		if resourceName == "" || accountName == "" {
			util.PrintErrorMessageAndExit("Both --resource and --account flags are required")
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

		pam.StartKubernetesLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, pam.PAMAccessParams{
			ResourceName: resourceName,
			AccountName:  accountName,
		}, projectID, durationStr, port)
	},
}

// ==================== Redis Commands ====================

var pamRedisCmd = &cobra.Command{
	Use:                   "redis",
	Short:                 "Redis-related PAM commands",
	Long:                  "Redis-related PAM commands for Infisical",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var pamRedisAccessCmd = &cobra.Command{
	Use:                   "access",
	Short:                 "Access PAM Redis accounts",
	Long:                  "Access PAM Redis accounts for Infisical. This starts a local Redis proxy server that you can use to connect to Redis directly.",
	Example:               "infisical pam redis access --resource my-redis-resource --account redis-admin --duration 4h --port 6379 --project-id <project_uuid>",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()

		resourceName, _ := cmd.Flags().GetString("resource")
		accountName, _ := cmd.Flags().GetString("account")

		if resourceName == "" || accountName == "" {
			util.PrintErrorMessageAndExit("Both --resource and --account flags are required")
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

		pam.StartRedisLocalProxy(loggedInUserDetails.UserCredentials.JTWToken, pam.PAMAccessParams{
			ResourceName: resourceName,
			AccountName:  accountName,
		}, projectID, durationStr, port)
	},
}

func init() {
	// Database commands
	pamDbCmd.AddCommand(pamDbAccessCmd)
	pamDbAccessCmd.Flags().String("resource", "", "Name of the PAM resource to access")
	pamDbAccessCmd.Flags().String("account", "", "Name of the account within the resource")
	pamDbAccessCmd.Flags().String("duration", "1h", "Duration for database access session (e.g., '1h', '30m', '2h30m')")
	pamDbAccessCmd.Flags().Int("port", 0, "Port for the local database proxy server (0 for auto-assign)")
	pamDbAccessCmd.Flags().String("project-id", "", "Project ID of the account to access")
	pamDbAccessCmd.MarkFlagRequired("resource")
	pamDbAccessCmd.MarkFlagRequired("account")

	// SSH commands
	pamSshCmd.AddCommand(pamSshAccessCmd)
	pamSshAccessCmd.Flags().String("resource", "", "Name of the PAM resource to access")
	pamSshAccessCmd.Flags().String("account", "", "Name of the account within the resource")
	pamSshAccessCmd.Flags().String("duration", "1h", "Duration for SSH access session (e.g., '1h', '30m', '2h30m')")
	pamSshAccessCmd.Flags().String("project-id", "", "Project ID of the account to access")
	pamSshAccessCmd.MarkFlagRequired("resource")
	pamSshAccessCmd.MarkFlagRequired("account")

	// Kubernetes commands
	pamKubernetesCmd.AddCommand(pamKubernetesAccessCmd)
	pamKubernetesAccessCmd.Flags().String("resource", "", "Name of the PAM resource to access")
	pamKubernetesAccessCmd.Flags().String("account", "", "Name of the account within the resource")
	pamKubernetesAccessCmd.Flags().String("duration", "1h", "Duration for kubernetes access session (e.g., '1h', '30m', '2h30m')")
	pamKubernetesAccessCmd.Flags().Int("port", 0, "Port for the local kubernetes proxy server (0 for auto-assign)")
	pamKubernetesAccessCmd.Flags().String("project-id", "", "Project ID of the account to access")
	pamKubernetesAccessCmd.MarkFlagRequired("resource")
	pamKubernetesAccessCmd.MarkFlagRequired("account")

	// Redis commands
	pamRedisCmd.AddCommand(pamRedisAccessCmd)
	pamRedisAccessCmd.Flags().String("resource", "", "Name of the PAM resource to access")
	pamRedisAccessCmd.Flags().String("account", "", "Name of the account within the resource")
	pamRedisAccessCmd.Flags().String("duration", "1h", "Duration for Redis access session (e.g., '1h', '30m', '2h30m')")
	pamRedisAccessCmd.Flags().Int("port", 0, "Port for the local Redis proxy server (0 for auto-assign)")
	pamRedisAccessCmd.Flags().String("project-id", "", "Project ID of the account to access")
	pamRedisAccessCmd.MarkFlagRequired("resource")
	pamRedisAccessCmd.MarkFlagRequired("account")

	pamCmd.AddCommand(pamDbCmd)
	pamCmd.AddCommand(pamSshCmd)
	pamCmd.AddCommand(pamKubernetesCmd)
	pamCmd.AddCommand(pamRedisCmd)
	RootCmd.AddCommand(pamCmd)
}
