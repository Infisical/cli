/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// projectsCmd groups CLI verbs for managing Infisical projects (workspaces).
// The subcommands emit machine-readable JSON when --json is set so that
// scripts and AI-agent bootstrap prompts can chain them without parsing
// human-oriented output.
var projectsCmd = &cobra.Command{
	Use:                   "projects",
	Short:                 "Manage Infisical projects (list and create)",
	DisableFlagsInUseLine: true,
	Example:               "infisical projects list --json\n  infisical projects create --name my-app --json",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var projectsListCmd = &cobra.Command{
	Use:                   "list",
	Short:                 "List projects the current user belongs to in the currently selected organization",
	DisableFlagsInUseLine: true,
	Example:               "infisical projects list\n  infisical projects list --json",
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
	Example:               "infisical projects create --name my-app\n  infisical projects create --name my-app --description \"backend service\" --json",
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

type projectListEntry struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	OrgID string `json:"orgId"`
}

func runProjectsList(cmd *cobra.Command, args []string) {
	jsonOut, _ := cmd.Flags().GetBool("json")

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
	//
	// Workspace's JSON tags mirror the API (_id, __v); emit the same field
	// names as `projects create --json` so agents can chain either command.
	projects := make([]projectListEntry, 0, len(resp.Workspaces))
	for _, w := range resp.Workspaces {
		if userCreds.OrganizationID == "" || w.OrganizationId == userCreds.OrganizationID {
			projects = append(projects, projectListEntry{ID: w.ID, Name: w.Name, OrgID: w.OrganizationId})
		}
	}

	if jsonOut {
		out, err := json.MarshalIndent(projects, "", "  ")
		if err != nil {
			util.HandleError(err, "Unable to encode JSON")
		}
		util.PrintlnStdout(string(out))
		return
	}

	if len(projects) == 0 {
		util.PrintlnStdout("No projects found for the currently selected organization.")
		return
	}
	util.PrintlnStdout("ID\tNAME\tORG ID")
	for _, p := range projects {
		util.PrintfStdout("%s\t%s\t%s\n", util.SanitizeDisplay(p.ID), util.SanitizeDisplay(p.Name), util.SanitizeDisplay(p.OrgID))
	}
	Telemetry.CaptureEvent("cli-command:projects list", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

func runProjectsCreate(cmd *cobra.Command, args []string) {
	name, _ := cmd.Flags().GetString("name")
	description, _ := cmd.Flags().GetString("description")
	slug, _ := cmd.Flags().GetString("slug")
	jsonOut, _ := cmd.Flags().GetBool("json")

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

	if jsonOut {
		out, err := json.MarshalIndent(project, "", "  ")
		if err != nil {
			util.HandleError(err, "Unable to encode JSON")
		}
		util.PrintlnStdout(string(out))
	} else {
		projectID := util.SanitizeDisplay(project.ID)
		util.PrintSuccessMessage(fmt.Sprintf("Created project %q (id: %s)", util.SanitizeDisplay(project.Name), projectID))
		if len(project.Environments) > 0 {
			util.PrintlnStdout("Environments:")
			for _, e := range project.Environments {
				util.PrintfStdout("  - %s (%s)\n", util.SanitizeDisplay(e.Name), util.SanitizeDisplay(e.Slug))
			}
		}
		util.PrintlnStdout("\nRun `infisical init --project-id " + projectID + "` to link this directory.")
	}

	Telemetry.CaptureEvent("cli-command:projects create", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

func init() {
	projectsListCmd.Flags().Bool("json", false, "Output the project list as JSON (id, name, orgId per entry). Useful for scripting and AI-agent bootstrap flows.")

	projectsCreateCmd.Flags().String("name", "", "Name of the project to create (required, 1-64 characters).")
	projectsCreateCmd.Flags().String("description", "", "Optional description of the project (up to 1024 characters).")
	projectsCreateCmd.Flags().String("slug", "", "Optional slug for the project (5-64 characters; auto-generated from the name when omitted).")
	projectsCreateCmd.Flags().Bool("json", false, "Output the created project as JSON. Useful for scripting and AI-agent bootstrap flows.")

	projectsCmd.AddCommand(projectsListCmd)
	projectsCmd.AddCommand(projectsCreateCmd)
	RootCmd.AddCommand(projectsCmd)
}
