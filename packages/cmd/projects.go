/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// projectsCmd groups CLI verbs for managing Infisical projects (workspaces).
var projectsCmd = &cobra.Command{
	Use:                   "projects",
	Short:                 "Manage Infisical projects (list and create)",
	DisableFlagsInUseLine: true,
	Example:               "infisical projects list\n  infisical projects create --name my-app",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var projectsListCmd = &cobra.Command{
	Use:                   "list",
	Short:                 "List projects the current user belongs to in the currently selected organization",
	DisableFlagsInUseLine: true,
	Example:               "infisical projects list",
	Args:                  cobra.NoArgs,
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: runProjectsList,
}

var projectsCreateCmd = &cobra.Command{
	Use:                   "create",
	Short:                 "Create a new project in the currently selected organization",
	DisableFlagsInUseLine: true,
	Example:               "infisical projects create --name my-app\n  infisical projects create --name my-app --description \"backend service\"",
	Args:                  cobra.NoArgs,
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: runProjectsCreate,
}

func projectsAuthedClient() (*resty.Client, util.LoggedInUserDetails, error) {
	userCreds := requireUserSession()

	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return nil, userCreds, err
	}
	httpClient.SetAuthToken(userCreds.UserCredentials.JTWToken)
	return httpClient, userCreds, nil
}

func runProjectsList(cmd *cobra.Command, args []string) {
	httpClient, userCreds, err := projectsAuthedClient()
	if err != nil {
		util.HandleError(err, "Unable to build authenticated HTTP client")
	}

	resp, err := api.CallGetAllWorkSpacesUserBelongsTo(httpClient)
	if err != nil {
		util.HandleError(err, "Unable to list projects")
	}

	// The endpoint returns projects across every organization the user
	// belongs to; keep only the session's organization, as `init` does, so a
	// script never picks a project it cannot link here.
	found := false
	for _, w := range resp.Workspaces {
		if userCreds.OrganizationID != "" && w.OrganizationId != userCreds.OrganizationID {
			continue
		}
		if !found {
			util.PrintlnStdout("ID\tNAME\tORG ID")
			found = true
		}
		util.PrintfStdout("%s\t%s\t%s\n", util.SanitizeDisplay(w.ID), util.SanitizeDisplay(w.Name), util.SanitizeDisplay(w.OrganizationId))
	}

	if !found {
		util.PrintlnStdout("No projects found for the currently selected organization.")
		return
	}
	Telemetry.CaptureEvent("cli-command:projects list", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

func runProjectsCreate(cmd *cobra.Command, args []string) {
	name, _ := cmd.Flags().GetString("name")
	description, _ := cmd.Flags().GetString("description")
	slug, _ := cmd.Flags().GetString("slug")
	if name == "" {
		util.PrintErrorMessageAndExit("--name is required")
	}

	httpClient, _, err := projectsAuthedClient()
	if err != nil {
		util.HandleError(err, "Unable to build authenticated HTTP client")
	}

	project, err := api.CallCreateProject(httpClient, api.CreateProjectRequest{
		ProjectName:             name,
		ProjectDescription:      description,
		Slug:                    slug,
		ShouldCreateDefaultEnvs: true,
	})
	if err != nil {
		util.HandleError(err, "Unable to create project")
	}

	projectID := util.SanitizeDisplay(project.ID)
	util.PrintSuccessMessage(fmt.Sprintf("Created project %q (id: %s)", util.SanitizeDisplay(project.Name), projectID))
	if len(project.Environments) > 0 {
		util.PrintlnStdout("Environments:")
		for _, e := range project.Environments {
			util.PrintfStdout("  - %s (%s)\n", util.SanitizeDisplay(e.Name), util.SanitizeDisplay(e.Slug))
		}
	}
	util.PrintlnStdout("\nRun `infisical init --project-id " + projectID + "` to link this directory.")

	Telemetry.CaptureEvent("cli-command:projects create", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

func init() {
	projectsCreateCmd.Flags().String("name", "", "Name of the project to create (required, 1-64 characters).")
	projectsCreateCmd.Flags().String("description", "", "Optional description of the project (up to 1024 characters).")
	projectsCreateCmd.Flags().String("slug", "", "Optional slug for the project (5-64 characters; auto-generated from the name when omitted).")

	projectsCmd.AddCommand(projectsListCmd)
	projectsCmd.AddCommand(projectsCreateCmd)
	RootCmd.AddCommand(projectsCmd)
}
