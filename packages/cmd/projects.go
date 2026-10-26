/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// secretManagerProjectType is the project type the `sm projects` commands list and create.
// Projects of other products (PKI, KMS, SSH, ...) are left to their own namespaces.
const secretManagerProjectType = "secret-manager"

// buildProjectsCmd builds the `infisical sm projects` command tree.
func buildProjectsCmd() *cobra.Command {
	projectsCmd := &cobra.Command{
		Use:     "projects",
		Aliases: []string{"project"},
		Short:   "List, inspect, and create Secrets Management projects",
		Example: `# List the projects in your organization
infisical sm projects list

# Show a project and its environments
infisical sm projects get --projectId=<project-id>

# Create a project, then link this directory to it
infisical sm projects create --name my-app
infisical init --project-id <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List the Secrets Management projects in your organization",
		Example: `infisical sm projects list

# With a machine identity access token
infisical sm projects list --token <access-token>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run:                   runProjectsList,
	}
	listCmd.Flags().String("token", "", "List projects using a machine identity access token")
	addProjectsOutputFlag(listCmd, "The output to format the projects in")
	projectsCmd.AddCommand(listCmd)

	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Show a project and its environments",
		Example: `infisical sm projects get --projectId=<project-id>

# The project this directory is linked to with infisical init
infisical sm projects get`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run:                   runProjectsGet,
	}
	getCmd.Flags().String("projectId", "", "project id (falls back to INFISICAL_PROJECT_ID, then .infisical.yaml or a legacy .infisical.json)")
	getCmd.Flags().String("token", "", "Get the project using a machine identity access token")
	addProjectsOutputFlag(getCmd, "The output to format the project in")
	projectsCmd.AddCommand(getCmd)

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a Secrets Management project with the default environments",
		Example: `infisical sm projects create --name my-app

# With a description and a custom slug
infisical sm projects create --name my-app --description "Backend service" --slug my-app-backend`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run:                   runProjectsCreate,
	}
	createCmd.Flags().String("name", "", "Name of the project, required (up to 64 characters)")
	createCmd.Flags().String("description", "", "Description of the project (up to 1024 characters)")
	createCmd.Flags().String("slug", "", "Slug of the project (5-64 characters, generated from the name when omitted)")
	createCmd.Flags().String("token", "", "Create the project using a machine identity access token")
	addProjectsOutputFlag(createCmd, "The output to format the created project in")
	projectsCmd.AddCommand(createCmd)

	return projectsCmd
}

var serviceTokenUnsupportedCommands = map[string]bool{
	"infisical sm projects list":   true,
	"infisical sm projects create": true,
}

// Reports whether cmd will skip token and use the login session instead,
// so the root command doesn't warn that the token overrides the session.
func ignoresEnvServiceToken(cmd *cobra.Command, token *models.TokenDetails) bool {
	return token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER && !cmd.Flags().Changed("token") && serviceTokenUnsupportedCommands[cmd.CommandPath()]
}

// projectsHTTPClient authenticates with the machine identity token from --token or the
// environment when there is one, and with the logged-in user's session otherwise.
func projectsHTTPClient(cmd *cobra.Command) *resty.Client {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		util.HandleError(err, "Unable to get resty client with custom headers")
	}

	if ignoresEnvServiceToken(cmd, token) {
		log.Debug().Msgf("Ignoring the service token from %s, which can't list or create projects", token.Source)
		token = nil
	}
	if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER && serviceTokenUnsupportedCommands[cmd.CommandPath()] {
		util.PrintErrorMessageAndExit("Service tokens can't list or create projects. Pass a machine identity access token with --token, or log in with [infisical login].")
	}

	if token != nil {
		httpClient.SetAuthToken(token.Token)
		return httpClient
	}

	util.RequireLogin()
	details := requireUserSession()
	httpClient.SetAuthToken(details.UserCredentials.JTWToken)
	return httpClient
}

func projectsOutputFormat(cmd *cobra.Command) string {
	outputFormat, err := cmd.Flags().GetString("output")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	if outputFormat != "" && !slices.Contains(util.SUPPORTED_OUTPUT_FORMATS, outputFormat) {
		_, err := util.FormatOutput(outputFormat, struct{}{}, nil)
		util.HandleError(err, "Unable to format output")
	}
	if outputFormat == util.OUTPUT_FORMAT_DOTENV {
		util.HandleError(fmt.Errorf("projects can't be output as dotenv; use json or yaml"))
	}
	return outputFormat
}

func addProjectsOutputFlag(cmd *cobra.Command, outputDescription string) {
	cmd.Flags().StringP("output", "o", "", outputDescription+". Supported formats are yaml, json")
}

// printProjectsTip prints a hint to stderr unless --silent is set.
func printProjectsTip(cmd *cobra.Command, tip string) {
	if silent, _ := cmd.Flags().GetBool("silent"); !silent {
		util.PrintlnStderr(tip)
	}
}

func printFormattedOutput[T any](outputFormat string, value T) {
	output, err := util.FormatOutput(outputFormat, value, nil)
	if err != nil {
		util.HandleError(err, "Unable to format output")
	}
	util.PrintStdout(output)
}

func runProjectsList(cmd *cobra.Command, args []string) {
	outputFormat := projectsOutputFormat(cmd)

	projects, err := api.CallListProjects(projectsHTTPClient(cmd), secretManagerProjectType)
	if err != nil {
		util.HandleError(err, "Unable to list projects")
	}

	if outputFormat != "" {
		printFormattedOutput(outputFormat, projects)
	} else if len(projects) == 0 {
		printProjectsTip(cmd, "No projects found in this organization. Create one with [infisical sm projects create --name <name>].")
	} else {
		visualize.PrintAllProjectsDetails(projects)
	}

	Telemetry.CaptureEvent("cli-command:projects list", posthog.NewProperties().Set("projectCount", len(projects)).Set("version", util.CLI_VERSION))
}

func runProjectsGet(cmd *cobra.Command, args []string) {
	outputFormat := projectsOutputFormat(cmd)

	projectID, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "projectId", []string{util.INFISICAL_PROJECT_ID_NAME}, "")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	if projectID == "" {
		notLinked := "Please either run infisical init to connect to a project, or pass in project id with --projectId flag (see [infisical sm projects list])"
		configFile, err := util.FindWorkspaceConfigFile()
		if err != nil {
			util.PrintErrorMessageAndExit(notLinked)
		}
		workspaceFile, err := util.GetWorkSpaceFromFilePath(filepath.Dir(configFile))
		if err != nil {
			util.HandleError(err, fmt.Sprintf("Unable to read the project config at %s", configFile))
		}
		if workspaceFile.WorkspaceId == "" {
			util.PrintErrorMessageAndExit(notLinked)
		}
		projectID = workspaceFile.WorkspaceId
	}

	project, err := api.CallGetProject(projectsHTTPClient(cmd), projectID)
	if err != nil {
		util.HandleError(err, "Unable to get the project")
	}
	if project.Type != "" && project.Type != secretManagerProjectType {
		util.HandleError(fmt.Errorf("project %s is a %s project, not a Secrets Management project", util.SanitizeDisplay(project.ID), util.SanitizeDisplay(project.Type)))
	}

	if outputFormat != "" {
		printFormattedOutput(outputFormat, project)
	} else {
		printProjectDetails(project)
	}

	Telemetry.CaptureEvent("cli-command:projects get", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

func runProjectsCreate(cmd *cobra.Command, args []string) {
	outputFormat := projectsOutputFormat(cmd)
	name, _ := cmd.Flags().GetString("name")
	name = strings.TrimSpace(name)
	if name == "" {
		util.HandleError(fmt.Errorf("the project name is required; pass --name"))
	}
	description, _ := cmd.Flags().GetString("description")
	slug, _ := cmd.Flags().GetString("slug")

	project, err := api.CallCreateProject(projectsHTTPClient(cmd), api.CreateProjectRequest{
		ProjectName:        name,
		ProjectDescription: description,
		Slug:               slug,
		Type:               secretManagerProjectType,
	})
	if err != nil {
		util.HandleError(err, "Unable to create the project")
	}

	if outputFormat != "" {
		printFormattedOutput(outputFormat, project)
	} else {
		util.PrintSuccessMessage(fmt.Sprintf("Created project %s", util.SanitizeDisplay(project.Name)))
		printProjectDetails(project)
	}

	// The ID ends up in a command the user may paste, so only suggest it when it is a plain UUID.
	if parsedID, err := uuid.Parse(project.ID); err == nil {
		printProjectsTip(cmd, fmt.Sprintf("\nLink this directory to it with [infisical init --project-id %s].", parsedID.String()))
	}

	Telemetry.CaptureEvent("cli-command:projects create", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

func printProjectDetails(project api.ProjectDetails) {
	visualize.PrintAllProjectsDetails([]api.ProjectDetails{project})
	if len(project.Environments) > 0 {
		visualize.PrintProjectEnvironments(project)
	}
}
