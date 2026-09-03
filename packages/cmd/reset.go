/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:     "reset",
	Short:   "Used to delete all Infisical related data on your machine",
	Example: "infisical reset",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		// revoke and delete every stored login session
		configFile, _ := util.GetConfigFile()
		util.MigrateConfigProfiles(&configFile)

		localOnly, err := cmd.Flags().GetBool("local-only")
		if err != nil {
			util.HandleError(err)
		}

		var profileNames []string
		for _, profile := range configFile.Profiles {
			profileNames = append(profileNames, profile.Name)
		}
		for _, result := range util.LogoutProfilesAcrossDomains(configFile, profileNames, localOnly) {
			if result.RevokeErr != nil {
				util.PrintWarning(fmt.Sprintf("Could not revoke the session for profile '%s' [err=%s]. It stays valid until it expires.", result.ProfileName, result.RevokeErr))
			}
		}

		keyringKeys := map[string]bool{}
		if configFile.LoggedInUserEmail != "" {
			keyringKeys[configFile.LoggedInUserEmail] = true
		}
		for _, user := range configFile.LoggedInUsers {
			if user.Email != "" {
				keyringKeys[user.Email] = true
			}
		}
		for _, profile := range configFile.Profiles {
			keyringKeys[profile.Name] = true
		}

		// delete from keyring
		for key := range keyringKeys {
			util.DeleteValueInKeyring(key)
		}

		// delete config
		_, pathToDir, err := util.GetFullConfigFilePath()
		if err != nil {
			util.HandleError(err)
		}

		os.RemoveAll(pathToDir)

		// delete secrets backup
		util.DeleteBackupSecrets()

		util.PrintSuccessMessage("Reset successful")
		Telemetry.CaptureEvent("cli-command:reset", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

func init() {
	resetCmd.Flags().Bool("local-only", false, "remove local data without revoking sessions on the server")
	RootCmd.AddCommand(resetCmd)
}
