/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/crypto"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

var tokensCmd = &cobra.Command{
	Use:                   "service-token",
	Short:                 "Manage service tokens",
	DisableFlagsInUseLine: true,
	Example:               "infisical service-token",
	Args:                  cobra.ExactArgs(0),
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var tokensCreateCmd = &cobra.Command{
	Use:                   "create",
	Short:                 "Used to create service tokens",
	DisableFlagsInUseLine: true,
	Example:               "infisical service-token create",
	Args:                  cobra.ExactArgs(0),
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: func(cmd *cobra.Command, args []string) {
		// get plain text workspace key
		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)

		if err != nil {
			util.HandleError(err, "Unable to retrieve your logged in your details. Please login in then try again")
		}

		if loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		tokenOnly := util.GetBooleanArgument(cmd, "token-only", "Unable to parse flag --token-only")

		projectConfig := util.GetWorkspaceConfigFromCommandOrFile(cmd)

		serviceTokenName := util.GetStringArgument(cmd, "name", "Unable to parse flag --name")

		expireSeconds := util.GetIntArgument(cmd, "expiry-seconds", "Unable to parse flag --expiry-seconds")

		scopes := util.GetStringSliceArgument(cmd, "scope", "Unable to parse flag --scope")

		if len(scopes) == 0 {
			util.PrintErrorMessageAndExit("You must define the environments and paths your service token should have access to via the --scope flag")
		}

		permissions := []api.ScopePermission{}

		for _, scope := range scopes {
			parts := strings.Split(scope, ":")

			if len(parts) != 2 {
				fmt.Println("--scope flag is malformed. Each scope flag should be in the following format: <env-slug>:<folder-path>")
				return
			}

			permissions = append(permissions, api.ScopePermission{Environment: parts[0], SecretPath: parts[1]})
		}

		accessLevels := util.GetStringSliceArgument(cmd, "access-level", "Unable to parse flag --access-level")

		if len(accessLevels) == 0 {
			util.PrintErrorMessageAndExit("You must define whether your service token can be used to read and or write via the --access-level flag")
		}

		for _, accessLevel := range accessLevels {
			if accessLevel != "read" && accessLevel != "write" {
				util.PrintErrorMessageAndExit("--access-level can only be of values read and write")
			}
		}

		randomBytes, err := crypto.GenerateRandomBytes(16)
		if err != nil {
			util.HandleError(err)
		}
		hexEncodedRandomBytes := hex.EncodeToString(randomBytes)

		// make a call to the api to save the encrypted symmetric key details
		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			util.HandleError(err, "Unable to get resty client with custom headers")
		}

		httpClient.SetAuthToken(loggedInUserDetails.UserCredentials.JTWToken).
			SetHeader("Accept", "application/json")

		createServiceTokenResponse, err := api.CallCreateServiceToken(httpClient, api.CreateServiceTokenRequest{
			Name:        serviceTokenName,
			WorkspaceId: projectConfig.WorkspaceId,
			Scopes:      permissions,
			ExpiresIn:   expireSeconds,
			Permissions: accessLevels,
			RandomBytes: hexEncodedRandomBytes,

			// No longer required for creating service tokens:
			EncryptedKey: "",
			Iv:           "",
			Tag:          "",
		})

		if err != nil {
			util.HandleError(err, "Unable to create service token")
		}

		serviceToken := createServiceTokenResponse.ServiceToken + "." + hexEncodedRandomBytes

		if tokenOnly {
			fmt.Println(serviceToken)
		} else {
			printablePermission := []string{}
			for _, permission := range permissions {
				printablePermission = append(printablePermission, fmt.Sprintf("([environment: %v] [path: %v])", permission.Environment, permission.SecretPath))
			}

			fmt.Printf("New service token created\n")
			fmt.Printf("Name: %v\n", serviceTokenName)
			fmt.Printf("Project ID: %v\n", projectConfig.WorkspaceId)
			fmt.Printf("Access type: [%v]\n", strings.Join(accessLevels, ", "))
			fmt.Printf("Permission(s): %v\n", strings.Join(printablePermission, ", "))
			fmt.Printf("Service Token: %v\n", serviceToken)
		}
	},
}

func init() {
	tokensCreateCmd.Flags().String("projectId", "", "The project ID you'd like to create the service token for. Default: will use linked Infisical project in .infisical.json")
	tokensCreateCmd.Flags().StringSliceP("scope", "s", []string{}, "Environment and secret path. Example format: <env-slug>:<folder-path>")
	tokensCreateCmd.Flags().StringP("name", "n", "Service token generated via CLI", "Service token name")
	tokensCreateCmd.Flags().StringSliceP("access-level", "a", []string{}, "The type of access the service token should have. Can be 'read' and or 'write'")
	tokensCreateCmd.Flags().Bool("token-only", false, "When true, only the service token will be printed")
	tokensCreateCmd.Flags().IntP("expiry-seconds", "e", 86400, "Set the service token's expiration time in seconds from now. To never expire set to zero. Default: 1 day ")

	tokensCmd.AddCommand(tokensCreateCmd)

	rootCmd.AddCommand(tokensCmd)
}
