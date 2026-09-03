/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "End a login session and revoke it on the server",
	Long: `End a login session.

The session is revoked on the server and its credentials are removed from this
machine. The profile itself is kept, so [infisical login --profile <name>] signs
back in without setting it up again.

Several profiles for the same account on the same machine share one server
session. A session another profile still uses is left intact, and only this
profile's stored credentials are removed.`,
	DisableFlagsInUseLine: true,
	Example:               "infisical logout\ninfisical logout --profile globex\ninfisical logout --all",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		all, err := cmd.Flags().GetBool("all")
		if err != nil {
			util.HandleError(err)
		}
		localOnly, err := cmd.Flags().GetBool("local-only")
		if err != nil {
			util.HandleError(err)
		}

		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "Unable to read the Infisical config file")
		}

		if len(configFile.Profiles) == 0 {
			util.PrintlnStderr("No login profiles found, so there is nothing to log out of.")
			return
		}

		var targetNames []string
		if all {
			for _, profile := range configFile.Profiles {
				targetNames = append(targetNames, profile.Name)
			}
		} else {
			resolved := util.ResolveProfile(configFile)
			if resolved.Name == "" {
				util.PrintErrorMessageAndExit("No profile is selected. Pass --profile <name>, or --all to log out of every profile.")
			}
			if _, found := util.FindProfile(configFile, resolved.Name); !found {
				util.PrintErrorMessageAndExit(fmt.Sprintf("Profile '%s' does not exist. Run [infisical profile list] to see available profiles.", resolved.Name))
			}
			targetNames = []string{resolved.Name}
		}

		// The domain follows the profile, so revocation must reach the instance
		// that issued the session rather than whatever default is configured.
		results := util.LogoutProfilesAcrossDomains(configFile, targetNames, localOnly)

		for _, result := range results {
			switch {
			case !result.HadSession:
				util.PrintlnStderr(fmt.Sprintf("Profile '%s' had no stored session.", result.ProfileName))
			case result.SharedWith != "":
				util.PrintlnStderr(fmt.Sprintf("Removed the stored session for profile '%s'. The server session is still used by profile '%s', so it was left active.", result.ProfileName, result.SharedWith))
			case result.RevokeErr != nil:
				util.PrintWarning(fmt.Sprintf("Removed the stored session for profile '%s', but could not revoke it on the server [err=%s]. It stays valid until it expires; you can revoke it from the web app.", result.ProfileName, result.RevokeErr))
			case result.Revoked:
				util.PrintlnStderr(fmt.Sprintf("Logged out of profile '%s' and revoked its session on the server.", result.ProfileName))
			default:
				util.PrintlnStderr(fmt.Sprintf("Removed the stored session for profile '%s'.", result.ProfileName))
			}

			if result.LocalErr != nil {
				util.PrintWarning(fmt.Sprintf("Unable to remove the stored credentials for profile '%s' [err=%s]", result.ProfileName, result.LocalErr))
			}
		}

		util.PrintlnStderr("\nProfiles are kept so you can sign back in with [infisical login --profile <name>]. Remove one entirely with [infisical profile delete <name>].")

		Telemetry.CaptureEvent("cli-command:logout", posthog.NewProperties().Set("all", all).Set("localOnly", localOnly).Set("version", util.CLI_VERSION))
	},
}

func init() {
	logoutCmd.Flags().Bool("all", false, "log out of every profile on this machine")
	logoutCmd.Flags().Bool("local-only", false, "remove the stored credentials without revoking the session on the server")
	RootCmd.AddCommand(logoutCmd)
}
