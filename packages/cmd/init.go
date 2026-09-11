/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/manifoldco/promptui"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var initCmd = &cobra.Command{
	Use:                   "init",
	Short:                 "Used to connect your local project with Infisical project",
	DisableFlagsInUseLine: true,
	Example:               "infisical init",
	Args:                  cobra.ExactArgs(0),
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: func(cmd *cobra.Command, args []string) {
		if util.WorkspaceConfigFileExistsInCurrentPath() {
			shouldOverride, err := shouldOverrideWorkspacePrompt()
			if err != nil {
				log.Error().Msg("Unable to parse your answer")
				log.Debug().Err(err)
				return
			}

			if !shouldOverride {
				return
			}
		}

		userCreds, err := util.GetCurrentLoggedInUserDetails(true)
		if err != nil {
			util.HandleError(err, "Unable to get your login details")
		}

		if userCreds.LoginExpired {
			userCreds = util.EstablishUserLoginSession()
		}

		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			util.HandleError(err, "Unable to get resty client with custom headers")
		}
		httpClient.SetAuthToken(userCreds.UserCredentials.JTWToken)

		// The profile already carries an organization (and --org can retarget it
		// for this command), so don't ask again. Only fall back to the picker
		// when the profile has no organization recorded, which happens for
		// sessions migrated from a CLI that predates profiles.
		selectedOrgID := userCreds.OrganizationID
		var selectedSubOrgName *string

		if selectedOrgID == "" {
			pickedOrgID, pickedSubOrgName, err := pickOrganization(httpClient, "Which Infisical organization would you like to select a project from?", userCreds.UserCredentials.Email)
			if err != nil {
				util.HandleError(err, "Unable to select organization")
			}
			selectedSubOrgName = pickedSubOrgName

			newSessionToken, err := selectOrganizationToken(userCreds.UserCredentials.JTWToken, userCreds.UserCredentials.Email, pickedOrgID)
			if err != nil {
				util.HandleError(err, "Unable to select organization")
			}

			// The session token is now scoped to the selected organization; record
			// it on the profile this invocation resolved to so later commands in
			// this project don't have to ask again.
			userCreds.UserCredentials.JTWToken = newSessionToken
			orgID, subOrgID := util.ParseTokenOrgClaims(newSessionToken)
			if orgID == "" {
				orgID = pickedOrgID
			}
			selectedOrgID = orgID

			updatedProfile := userCreds.Profile
			updatedProfile.OrganizationID = orgID
			updatedProfile.SubOrganizationID = subOrgID
			updatedProfile.OrganizationName = util.OrgDisplayName(newSessionToken, orgID, subOrgID)

			// Only move the global default when this invocation was using it; a
			// terminal pinned via env var, flag, or directory scope must not switch
			// other terminals.
			makeActive := userCreds.ProfileSource == util.ProfileSourceDefault
			err = util.PersistLoginProfile(updatedProfile, &userCreds.UserCredentials, makeActive)
			httpClient.SetAuthToken(newSessionToken)

			if err != nil {
				util.HandleError(err, "Unable to store your user credentials")
			}
		} else {
			orgDisplay := userCreds.OrganizationName
			if orgDisplay == "" {
				orgDisplay = selectedOrgID
			}
			util.PrintlnStderr(fmt.Sprintf("Using organization %s from profile '%s'. Pass --org to pick a different one.", orgDisplay, userCreds.ProfileName))

			// An --org override is per command, so a project linked under it would
			// not resolve on later runs that use the profile's default.
			if userCreds.OrganizationSource != util.OrgSourceProfileDefault && userCreds.Profile.OrganizationID != "" && userCreds.OrganizationID != userCreds.Profile.OrganizationID {
				profileOrg := userCreds.Profile.OrganizationName
				if profileOrg == "" {
					profileOrg = userCreds.Profile.OrganizationID
				}
				util.PrintWarning(fmt.Sprintf("Profile '%s' defaults to organization %s, so later commands here will not find this project unless you pass --org again. Run [infisical profile set-org %s] to make it the default.", userCreds.ProfileName, profileOrg, orgDisplay))
			}
		}

		workspaceResponse, err := api.CallGetAllWorkSpacesUserBelongsTo(httpClient)
		if err != nil {
			util.HandleError(err, "Unable to pull projects that belong to you")
		}

		filteredWorkspaces, workspaceNames := util.GetWorkspacesInOrganization(workspaceResponse, selectedOrgID, selectedSubOrgName)

		prompt := promptui.Select{
			Label: "Which of your Infisical projects would you like to connect this project to?",
			Items: workspaceNames,
			Size:  7,
		}

		index, _, err := prompt.Run()
		if err != nil {
			util.HandleError(err)
		}

		err = writeWorkspaceFile(filteredWorkspaces[index])
		if err != nil {
			util.HandleError(err)
		}

		offerDirectoryProfileBinding(userCreds.ProfileName)

		Telemetry.CaptureEvent("cli-command:init", posthog.NewProperties().Set("version", util.CLI_VERSION))

	},
}

// offerDirectoryProfileBinding asks (only when multiple profiles exist)
// whether this directory should always use the profile init just ran with, so
// commands run here pick the right tenant without flags or env vars.
func offerDirectoryProfileBinding(profileName string) {
	configFile, err := util.GetMigratedConfigFile()
	if err != nil || profileName == "" || len(configFile.Profiles) < 2 {
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		return
	}

	if boundProfile, _, ok := util.FindGoverningDirectoryProfile(configFile, cwd); ok && boundProfile == profileName {
		return
	}

	prompt := promptui.Select{
		Label: fmt.Sprintf("Bind this directory to profile '%s'? Commands run here will then select it automatically. Select[Yes/No]", profileName),
		Items: []string{"No", "Yes"},
	}
	_, result, err := prompt.Run()
	if err != nil || result != "Yes" {
		return
	}

	util.SetDirectoryProfile(&configFile, cwd, profileName)
	if err := util.WriteConfigFile(&configFile); err != nil {
		util.PrintWarning(fmt.Sprintf("Unable to save the directory profile binding [err=%s]", err))
		return
	}
	util.PrintlnStderr(fmt.Sprintf("Directory %s now uses profile '%s'. Manage bindings with [infisical profile bind] and [infisical profile unbind].", cwd, profileName))
}

func init() {
	RootCmd.AddCommand(initCmd)
}

// pickOrganization prompts the user to select an organization (and optionally a sub-org).
// GET /v1/organization is always used as the source of truth for the org list.
// GET /v1/organization/accessible-with-sub-orgs is used only to enrich entries with sub-org
// counts and the second-level picker — if it fails or omits an org, that org still appears.
func pickOrganization(httpClient *resty.Client, label string, username string) (string, *string, error) {
	orgResp, err := api.CallGetAllOrganizations(httpClient)
	if err != nil {
		return "", nil, err
	}
	orgs := orgResp.Organizations
	if len(orgs) == 0 {
		util.PrintErrorMessageAndExit(fmt.Sprintf("You don't have any organization created in Infisical. You must first create a organization at %s", config.INFISICAL_URL))
	}

	// Best-effort: enrich with sub-org data. Ignore any error — the flat list is enough.
	subOrgsByOrgID := map[string][]api.SubOrganization{}
	if subOrgsResp, err := api.CallGetAllOrganizationsWithSubOrgs(httpClient); err != nil {
		log.Debug().Err(err).Str("username", username).Msg("Failed to fetch sub-org data; falling back to flat org list")
	} else {
		for _, o := range subOrgsResp.Organizations {
			subOrgsByOrgID[o.ID] = o.SubOrganizations
		}
	}

	labels := util.BuildOrgRootLabels(orgs, subOrgsByOrgID)

	prompt1 := promptui.Select{
		Label: label,
		Items: labels,
		Size:  7,
	}
	index, _, err := prompt1.Run()
	if err != nil {
		return "", nil, err
	}

	selectedOrg := orgs[index]
	subs := subOrgsByOrgID[selectedOrg.ID]

	if len(subs) == 0 {
		return selectedOrg.ID, nil, nil
	}

	// Second prompt: root org itself or one of its sub-orgs
	subItems, subLabels := util.BuildSubOrgPickerItems(selectedOrg.ID, selectedOrg.Name, subs)
	prompt2 := promptui.Select{
		Label: fmt.Sprintf("Select the root or sub-organization within %s", selectedOrg.Name),
		Items: subLabels,
		Size:  7,
	}
	subIndex, _, err := prompt2.Run()
	if err != nil {
		return "", nil, err
	}
	// Root org item is explicitly labeled with "(organization)"; any other selection is a sub-org name.
	if subIndex == 0 {
		return subItems[subIndex].ID, nil, nil
	}
	selectedSubOrgName := subs[subIndex-1].Name
	return subItems[subIndex].ID, &selectedSubOrgName, nil
}

func writeWorkspaceFile(selectedWorkspace models.Workspace) error {
	workspaceFileToSave := models.WorkspaceConfigFile{
		WorkspaceId: selectedWorkspace.ID,
	}

	marshalledWorkspaceFile, err := json.MarshalIndent(workspaceFileToSave, "", "    ")
	if err != nil {
		return err
	}

	err = util.WriteToFile(util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME, marshalledWorkspaceFile, 0600)
	if err != nil {
		return err
	}

	return nil
}

func shouldOverrideWorkspacePrompt() (bool, error) {
	prompt := promptui.Select{
		Label: "A workspace config file already exists here. Would you like to override? Select[Yes/No]",
		Items: []string{"No", "Yes"},
	}
	_, result, err := prompt.Run()
	if err != nil {
		return false, err
	}
	return result == "Yes", nil
}
