/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var orgCmd = &cobra.Command{
	Use:   "org",
	Short: "List organizations and change which one your profile uses",
	Long: `List organizations and change which one your profile uses.

The organization is a setting on your login profile, not a separate login. Use
[infisical profile current] to see the profile and organization in effect, and
--org on any command to use a different organization just for that command.`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var orgListCmd = &cobra.Command{
	Use:                   "list",
	Short:                 "List the organizations this profile's account can use",
	DisableFlagsInUseLine: true,
	Example:               "infisical org list",
	Args:                  cobra.NoArgs,
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: func(cmd *cobra.Command, args []string) {
		details := requireUserSession()

		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			util.HandleError(err, "Unable to get resty client with custom headers")
		}
		httpClient.SetAuthToken(details.UserCredentials.JTWToken)

		currentOrgID := details.OrganizationID
		if claimOrgID, _ := util.ParseTokenOrgClaims(details.UserCredentials.JTWToken); claimOrgID != "" {
			currentOrgID = claimOrgID
		}

		writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(writer, "CURRENT\tNAME\tSLUG\tID")

		marker := func(id string) string {
			if id == currentOrgID {
				return "*"
			}
			return ""
		}

		// The sub-org aware listing carries slugs and nested organizations.
		// Older instances may not have it, so fall back to the flat list.
		if subOrgsResp, err := api.CallGetAllOrganizationsWithSubOrgs(httpClient); err == nil && len(subOrgsResp.Organizations) > 0 {
			for _, org := range subOrgsResp.Organizations {
				fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", marker(org.ID), util.SanitizeDisplay(org.Name), util.SanitizeDisplay(org.Slug), org.ID)
				for _, sub := range org.SubOrganizations {
					fmt.Fprintf(writer, "%s\t  └─ %s\t%s\t%s\n", marker(sub.ID), util.SanitizeDisplay(sub.Name), util.SanitizeDisplay(sub.Slug), sub.ID)
				}
			}
		} else {
			orgResp, err := api.CallGetAllOrganizations(httpClient)
			if err != nil {
				util.HandleError(err, "Unable to list your organizations")
			}
			for _, org := range orgResp.Organizations {
				fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", marker(org.ID), util.SanitizeDisplay(org.Name), "", org.ID)
			}
		}
		writer.Flush()

		util.PrintlnStderr(fmt.Sprintf("\nProfile '%s' currently uses the organization marked above. Change it with [infisical profile set-org <name>], or use another one for a single command with --org <name>.", details.ProfileName))

		Telemetry.CaptureEvent("cli-command:org list", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

// newSetOrgCommand builds the command that changes a profile's default
// organization. It is registered twice, as [infisical profile set-org] (the
// canonical name, which says what it changes) and as [infisical org switch]
// (the name people reach for), so both lead to the same behavior.
// newSetOrgCommand builds the set-org command. invocation is the full command
// path as a user types it ("profile set-org" / "org switch"), used for examples.
func newSetOrgCommand(use string, invocation string, short string) *cobra.Command {
	command := &cobra.Command{
		Use:   use,
		Short: short,
		Long: `Set the organization a profile uses by default.

This changes a setting on the profile, so it persists for future commands. To
use a different organization for a single command instead, pass --org, and to
keep a second organization available as its own profile use
[infisical profile new].`,
		DisableFlagsInUseLine: true,
		Example:               fmt.Sprintf("infisical %s\ninfisical %s globex", invocation, invocation),
		Args:                  cobra.MaximumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			util.RequireLogin()
		},
		Run: runSetOrg,
	}

	command.Flags().String("org-id", "", "the id of the organization to use (deprecated, pass the organization as an argument instead)")
	return command
}

func runSetOrg(cmd *cobra.Command, args []string) {
	orgIDFlag, err := cmd.Flags().GetString("org-id")
	if err != nil {
		util.HandleError(err)
	}
	// This command does its own organization exchange, which can prompt for
	// MFA, so resolve the session with the --org override suspended.
	globalOrgSelector, _ := util.GetOrgOverride()
	restoreOrgOverride := util.SuspendOrgOverride()
	details := requireUserSession()
	restoreOrgOverride()

	// The organization can come from a positional argument (name, slug, or id),
	// the deprecated --org-id flag, the global --org flag, or the picker.
	selector := orgIDFlag
	if selector == "" {
		selector = globalOrgSelector
	}
	if len(args) == 1 {
		selector = args[0]
	}

	var selectedOrgID string
	if selector != "" {
		resolvedOrg, err := util.ResolveOrgSelector(details.UserCredentials.JTWToken, selector)
		if err != nil {
			util.HandleError(err)
		}
		selectedOrgID = resolvedOrg.ID
	} else {
		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			util.HandleError(err, "Unable to get resty client with custom headers")
		}
		httpClient.SetAuthToken(details.UserCredentials.JTWToken)

		selectedOrgID, _, err = pickOrganization(httpClient, fmt.Sprintf("Which organization should profile '%s' use?", details.ProfileName), details.UserCredentials.Email)
		if err != nil {
			util.HandleError(err, "Unable to select organization")
		}
	}

	newSessionToken, err := selectOrganizationToken(details.UserCredentials.JTWToken, details.UserCredentials.Email, selectedOrgID)
	if err != nil {
		util.HandleError(err, "Unable to change organization")
	}

	orgID, subOrgID := util.ParseTokenOrgClaims(newSessionToken)
	if orgID == "" {
		orgID = selectedOrgID
	}
	orgName := util.OrgDisplayName(newSessionToken, orgID, subOrgID)

	profile := details.Profile
	profile.OrganizationID = orgID
	profile.OrganizationName = orgName
	profile.SubOrganizationID = subOrgID

	credentials := details.UserCredentials
	credentials.JTWToken = newSessionToken

	// Only move the global default when this invocation was using it; a
	// terminal pinned via env var, flag, or directory scope must not switch
	// other terminals.
	makeActive := details.ProfileSource == util.ProfileSourceDefault
	if err := util.PersistLoginProfile(profile, &credentials, makeActive); err != nil {
		util.HandleError(err, "Unable to store your user credentials")
	}

	orgDisplay := orgName
	if orgDisplay == "" {
		orgDisplay = orgID
	}

	util.PrintlnStderr(fmt.Sprintf("Profile '%s' now uses organization %s by default.", profile.Name, orgDisplay))
	util.PrintlnStderr(fmt.Sprintf("To keep both organizations available at once, create a second profile with [infisical profile new <name> --org %s].", orgDisplay))
	if !makeActive {
		util.PrintlnStderr(fmt.Sprintf("This shell selects its profile via the %s. Use --profile %s or INFISICAL_PROFILE=%s to target the updated profile here.", details.ProfileSource, profile.Name, profile.Name))
	}

	Telemetry.CaptureEvent("cli-command:org switch", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

// requireUserSession loads the resolved profile's session, triggering the
// interactive login flow when it is missing or expired.
func requireUserSession() util.LoggedInUserDetails {
	details, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil {
		util.HandleError(err, "Unable to get your login details")
	}
	if details.LoginExpired {
		details = util.EstablishUserLoginSession()
	}
	return details
}

// selectOrganizationToken exchanges the given session token for one scoped to
// orgID, walking the user through MFA when the organization requires it.
func selectOrganizationToken(sessionToken string, email string, orgID string) (string, error) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return "", fmt.Errorf("unable to get resty client with custom headers [err=%w]", err)
	}
	httpClient.SetAuthToken(sessionToken)

	tokenResponse, err := api.CallSelectOrganization(httpClient, api.SelectOrganizationRequest{OrganizationId: orgID})
	if err != nil {
		return "", err
	}

	if tokenResponse.MfaEnabled {
		i := 1
		for i < 6 {
			mfaVerifyCode := askForMFACode(tokenResponse.MfaMethod)

			httpClient, err := util.GetRestyClientWithCustomHeaders()
			if err != nil {
				return "", fmt.Errorf("unable to get resty client with custom headers [err=%w]", err)
			}
			httpClient.SetAuthToken(tokenResponse.Token)
			verifyMFAresponse, mfaErrorResponse, requestError := api.CallVerifyMfaToken(httpClient, api.VerifyMfaTokenRequest{
				Email:     email,
				MFAToken:  mfaVerifyCode,
				MFAMethod: tokenResponse.MfaMethod,
			})
			if requestError != nil {
				return "", requestError
			} else if mfaErrorResponse != nil {
				if mfaErrorResponse.Context.Code == "mfa_invalid" {
					msg := fmt.Sprintf("Incorrect, verification code. You have %v attempts left", 5-i)
					util.PrintlnStderr(msg)
					if i == 5 {
						util.PrintErrorMessageAndExit("No tries left, please try again in a bit")
						break
					}
				}

				if mfaErrorResponse.Context.Code == "mfa_expired" {
					util.PrintErrorMessageAndExit("Your 2FA verification code has expired, please try logging in again")
					break
				}
				i++
			} else {
				httpClient.SetAuthToken(verifyMFAresponse.Token)
				tokenResponse, err = api.CallSelectOrganization(httpClient, api.SelectOrganizationRequest{OrganizationId: orgID})
				if err != nil {
					return "", err
				}
				break
			}
		}
	}

	return tokenResponse.Token, nil
}

func init() {
	orgCmd.AddCommand(orgListCmd)
	orgCmd.AddCommand(newSetOrgCommand("switch [org]", "org switch", "Change the organization this profile uses (same as [infisical profile set-org])"))
	RootCmd.AddCommand(orgCmd)
}
