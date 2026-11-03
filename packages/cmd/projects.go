/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"bytes"
	"errors"
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

// buildProjectsCmd builds the `infisical secrets-manager projects` command tree.
func buildProjectsCmd() *cobra.Command {
	projectsCmd := &cobra.Command{
		Use:     "projects",
		Aliases: []string{"project"},
		Short:   "Show, create, update, and delete Secrets Management projects",
		Example: `# List the projects in your organization
infisical secrets-manager projects get

# Show a project and its environments
infisical secrets-manager projects get my-app

# Create a project, then link this directory to it
infisical secrets-manager projects create --name my-app
infisical init --project-id <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	// Hidden but still working: `projects get` with no slug lists, like get does for every resource.
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List the Secrets Management projects in your organization",
		Example: `infisical secrets-manager projects list

# With a machine identity access token
infisical secrets-manager projects list --token <access-token>`,
		Hidden:                true,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run:                   runProjectsList,
		Annotations:           serviceTokenUnsupported,
	}
	listCmd.Flags().String("token", "", "List projects using a machine identity access token")
	addProjectsOutputFlag(listCmd, "The output to format the projects in")
	projectsCmd.AddCommand(listCmd)

	getCmd := &cobra.Command{
		Use:   "get [slug-or-id]",
		Short: "List your Secrets Management projects, or show one and its environments",
		Long: `List your Secrets Management projects, or show one and its environments.

Name the project by its slug or its ID. Without one, lists the projects in your organization. It
doesn't use INFISICAL_PROJECT_ID or .infisical.yaml to pick one.`,
		Example: `# Every Secrets Management project in your organization
infisical secrets-manager projects get

# One project and its environments
infisical secrets-manager projects get my-app

# By ID, which also works with a service token
infisical secrets-manager projects get <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run:                   runProjectsGet,
		Annotations:           serviceTokenOnlyByID,
	}
	getCmd.Flags().String("projectId", "", "ID of the project to show")
	_ = getCmd.Flags().MarkHidden("projectId")
	_ = getCmd.Flags().MarkDeprecated("projectId", "pass the project's slug or ID as the argument instead: infisical secrets-manager projects get <slug-or-id>")
	// pflag writes the deprecation notice while it parses, before -o and --silent are known, so it's
	// held here and printed once they are: never into -o json or yaml, whose stderr must stay one
	// JSON or YAML document.
	var flagNotices bytes.Buffer
	getCmd.Flags().SetOutput(&flagNotices)
	getCmd.PreRun = func(cmd *cobra.Command, args []string) {
		silent, _ := cmd.Flags().GetBool("silent")
		if flagNotices.Len() > 0 && !silent && !isStructuredOutputRequested(cmd) {
			fmt.Fprint(util.GetStderrWriter(), flagNotices.String())
		}
		flagNotices.Reset()
	}
	getCmd.Flags().String("token", "", "Get the project using a machine identity access token")
	addProjectsOutputFlag(getCmd, "The output to format the project in")
	projectsCmd.AddCommand(getCmd)

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a Secrets Management project with the default environments",
		Example: `infisical secrets-manager projects create --name my-app

# With a description and a custom slug
infisical secrets-manager projects create --name my-app --description "Backend service" --slug my-app-backend`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run:                   runProjectsCreate,
		Annotations:           serviceTokenUnsupported,
	}
	createCmd.Flags().String("name", "", "Name of the project, required (up to 64 characters)")
	createCmd.Flags().String("description", "", "Description of the project (up to 1024 characters)")
	createCmd.Flags().String("slug", "", "Slug of the project (5-64 characters, generated from the name when omitted)")
	createCmd.Flags().String("token", "", "Create the project using a machine identity access token")
	addProjectsOutputFlag(createCmd, "The output to format the created project in")
	projectsCmd.AddCommand(createCmd)

	updateCmd := &cobra.Command{
		Use:   "update <slug-or-id>",
		Short: "Change a Secrets Management project's name, slug, or description",
		Example: `infisical secrets-manager projects update my-app --name "My App"
infisical secrets-manager projects update my-app --slug my-app-backend

# Clear the description
infisical secrets-manager projects update <project-id> --description ""`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runProjectsUpdate,
		Annotations:           serviceTokenUnsupported,
	}
	updateCmd.Flags().String("name", "", "New name (up to 64 characters)")
	updateCmd.Flags().String("slug", "", "New slug (up to 64 characters). Commands that name the project by its old slug stop working")
	updateCmd.Flags().String("description", "", `New description (up to 1024 characters). Pass "" to clear it`)
	updateCmd.Flags().String("token", "", "Update the project using a machine identity access token")
	addProjectsOutputFlag(updateCmd, "The output to format the updated project in")
	projectsCmd.AddCommand(updateCmd)

	deleteCmd := &cobra.Command{
		Use:   "delete <slug>",
		Short: "Delete a Secrets Management project and all of its environments and secrets",
		Example: `infisical secrets-manager projects delete my-app

# Delete without asking for confirmation
infisical secrets-manager projects delete my-app --yes`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runProjectsDelete,
		Annotations:           serviceTokenUnsupported,
	}
	deleteCmd.Flags().String("token", "", "Delete the project using a machine identity access token")
	addConfirmFlags(deleteCmd)
	addProjectsOutputFlag(deleteCmd, "The output to format the deleted project in")
	projectsCmd.AddCommand(deleteCmd)

	return projectsCmd
}

const serviceTokenAnnotation = "infisical.serviceToken"

// serviceTokenUnsupported marks a command whose API routes reject service tokens. It is an
// annotation rather than a list of command paths so it holds under every alias of the command.
var serviceTokenUnsupported = map[string]string{serviceTokenAnnotation: "unsupported"}

// serviceTokenOnlyByID marks projects get, which accepts service tokens only for a lookup by ID:
// listing and the lookup by slug use routes that reject them.
var serviceTokenOnlyByID = map[string]string{serviceTokenAnnotation: "only-by-id"}

func rejectsServiceTokens(cmd *cobra.Command) bool {
	return cmd.Annotations[serviceTokenAnnotation] == "unsupported"
}

func rejectsServiceTokensFor(cmd *cobra.Command, args []string) bool {
	if cmd.Annotations[serviceTokenAnnotation] == "only-by-id" {
		if len(args) > 0 {
			return !isProjectID(args[0])
		}
		return !cmd.Flags().Changed("projectId")
	}
	return rejectsServiceTokens(cmd)
}

// Reports whether cmd will skip token and use the login session instead,
// so the root command doesn't warn that the token overrides the session.
func ignoresEnvServiceToken(cmd *cobra.Command, args []string, token *models.TokenDetails) bool {
	return token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER && !cmd.Flags().Changed("token") && rejectsServiceTokensFor(cmd, args)
}

func projectsHTTPClient(cmd *cobra.Command) *resty.Client {
	return secretsManagerHTTPClient(cmd, "list or create projects")
}

// secretsManagerHTTPClient authenticates with the machine identity token from --token or the
// environment when there is one, and with the logged-in user's session otherwise. what names what a
// service token can't do, for a command marked serviceTokenUnsupported.
func secretsManagerHTTPClient(cmd *cobra.Command, what string) *resty.Client {
	return secretsManagerHTTPClientRejecting(cmd, what, rejectsServiceTokens(cmd))
}

// secretsManagerHTTPClientRejecting is secretsManagerHTTPClient for a request whose route rejects
// service tokens even though the command's other routes accept them, such as projects get by slug.
func secretsManagerHTTPClientRejecting(cmd *cobra.Command, what string, rejectServiceTokens bool) *resty.Client {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		util.HandleError(err, "Unable to get resty client with custom headers")
	}

	isServiceToken := token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER
	ignoredServiceToken := rejectServiceTokens && isServiceToken && !cmd.Flags().Changed("token")
	if ignoredServiceToken {
		log.Debug().Msgf("Ignoring the service token from %s, which can't %s", token.Source, what)
		token, isServiceToken = nil, false
	}
	if rejectServiceTokens && isServiceToken {
		exitWithError(cmd, errServiceTokenUnsupported(what, "pass a machine identity access token with --token, or log in",
			util.NextStep{Purpose: "To log in", Command: "infisical login"}))
	}

	if token != nil {
		httpClient.SetAuthToken(token.Token)
		return httpClient
	}

	// The login below opens a browser and waits, which hangs a script or an agent: without a terminal,
	// or when it asked for -o json or yaml, a missing or expired session is an error instead. So is one
	// behind an ignored service token: whoever set INFISICAL_TOKEN expected it to be used, not a login.
	if ignoredServiceToken || !stdinIsTerminal() || errorOutputFormat(cmd) != "" {
		details, err := util.GetCurrentLoggedInUserDetails(true)
		if err != nil && !errors.Is(err, util.ErrUserNotLoggedIn) {
			util.HandleError(err, "Unable to get your login details")
		}
		// A profile whose keyring credentials are gone is just as logged out as having no profile.
		if err != nil || !details.IsUserLoggedIn || details.LoginExpired {
			if ignoredServiceToken {
				exitWithError(cmd, errServiceTokenUnsupported(what, "the one in INFISICAL_TOKEN can't be used, so pass a machine identity access token with --token, or log in",
					util.NextStep{Purpose: "To log in", Command: "infisical login"}))
			}
			exitWithError(cmd, errAuthRequired(err))
		}
		httpClient.SetAuthToken(details.UserCredentials.JTWToken)
		return httpClient
	}

	util.RequireLogin()
	details := requireUserSession()
	httpClient.SetAuthToken(details.UserCredentials.JTWToken)
	return httpClient
}

func projectsOutputFormat(cmd *cobra.Command) string {
	return crudOutputFormat(cmd, "projects")
}

func crudOutputFormat(cmd *cobra.Command, noun string) string {
	outputFormat, err := cmd.Flags().GetString("output")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	if outputFormat != "" && !slices.Contains(util.SUPPORTED_OUTPUT_FORMATS, outputFormat) {
		_, err := util.FormatOutput(outputFormat, struct{}{}, nil)
		util.HandleError(err, "Unable to format output")
	}
	if outputFormat == util.OUTPUT_FORMAT_DOTENV {
		util.HandleError(fmt.Errorf("%s can't be output as dotenv; use json or yaml", noun))
	}
	return outputFormat
}

func addProjectsOutputFlag(cmd *cobra.Command, outputDescription string) {
	cmd.Flags().StringP("output", "o", "", outputDescription+". Supported formats are yaml, json")
}

// printProjectsTip prints a hint to stderr unless --silent is set.
// Tips and notices repeat names from the backend, such as a project's, so they're redacted like errors.
func printProjectsTip(cmd *cobra.Command, tip string) {
	if silent, _ := cmd.Flags().GetBool("silent"); !silent {
		util.PrintlnStderr(util.RedactCredentials(tip))
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
	listProjects(cmd, projectsHTTPClient(cmd), projectsOutputFormat(cmd))
}

func listProjects(cmd *cobra.Command, client *resty.Client, outputFormat string) {
	projects, err := api.CallListProjects(client, secretManagerProjectType)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, errorScope{}, nil), "Unable to list projects")
	}

	if outputFormat != "" {
		printFormattedOutput(outputFormat, projects)
	} else if len(projects) == 0 {
		printProjectsTip(cmd, "No projects found in this organization. Create one with [infisical secrets-manager projects create --name <name>].")
	} else {
		visualize.PrintAllProjectsDetails(projects)
	}

	Telemetry.CaptureEvent("cli-command:projects list", posthog.NewProperties().Set("projectCount", len(projects)).Set("version", util.CLI_VERSION))
}

// isProjectID reports whether a projects get argument is a project ID rather than a slug. Project IDs
// are UUIDs, written the way the API returns them.
func isProjectID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func runProjectsGet(cmd *cobra.Command, args []string) {
	outputFormat := projectsOutputFormat(cmd)
	if len(args) == 1 {
		if cmd.Flags().Changed("projectId") {
			exitWithError(cmd, errProjectSlugAndID())
		}
		if isProjectID(args[0]) {
			getProjectByID(cmd, args[0], outputFormat)
			return
		}
		runProjectsGetBySlug(cmd, args[0], outputFormat)
		return
	}

	// Without a slug, ID or --projectId, get lists, like it does for every resource. It doesn't fall back
	// to INFISICAL_PROJECT_ID or .infisical.yaml, which would make it mean something else in a linked
	// directory.
	if !cmd.Flags().Changed("projectId") {
		listProjects(cmd, secretsManagerHTTPClientRejecting(cmd, "list projects", true), outputFormat)
		return
	}
	projectID, _ := cmd.Flags().GetString("projectId")
	if projectID = strings.TrimSpace(projectID); projectID == "" {
		exitWithError(cmd, errEmptyProjectID())
	}
	getProjectByID(cmd, projectID, outputFormat)
}

func getProjectByID(cmd *cobra.Command, projectID, outputFormat string) {
	project := secretsManagerProjectByID(cmd, projectsHTTPClient(cmd), projectID)
	if outputFormat != "" {
		printFormattedOutput(outputFormat, project)
	} else {
		printProjectDetails(project)
	}

	Telemetry.CaptureEvent("cli-command:projects get", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

// resolveProjectID is the project a command works on: --projectId, then INFISICAL_PROJECT_ID, then
// .infisical.yaml (or a legacy .infisical.json). It is "" when none is set.
func resolveProjectID(cmd *cobra.Command) string {
	projectID, _, err := util.ResolveProjectIDWithSource(cmd)
	var configErr *util.WorkspaceConfigError
	if errors.As(err, &configErr) {
		exitWithError(cmd, errProjectConfigInvalid(configErr.Path, configErr.Err))
	}
	return projectID
}

func runProjectsGetBySlug(cmd *cobra.Command, slug, outputFormat string) {
	// Only a service token passed with --token is refused; one in INFISICAL_TOKEN is ignored in favor of
	// the login session, as the other project commands do.
	if token, _ := util.GetInfisicalToken(cmd); token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER && cmd.Flags().Changed("token") {
		exitWithError(cmd, errServiceTokenUnsupported("look up a project by slug", "pass the project's ID instead, or use a machine identity access token",
			util.NextStep{Purpose: "To get the project by its ID", Command: secretsManagerPrefix + " projects get <project-id>"}))
	}

	project := secretsManagerProjectBySlug(cmd, secretsManagerHTTPClientRejecting(cmd, "look up a project by slug", true), slug)
	if outputFormat != "" {
		printFormattedOutput(outputFormat, project.ProjectDetails)
	} else {
		printProjectDetails(project.ProjectDetails)
	}

	Telemetry.CaptureEvent("cli-command:projects get", posthog.NewProperties().Set("bySlug", true).Set("version", util.CLI_VERSION))
}

// secretsManagerProject finds the project by its slug or its ID, the way projects get takes it.
func secretsManagerProject(cmd *cobra.Command, client *resty.Client, slugOrID string) api.ProjectDetails {
	if isProjectID(slugOrID) {
		return secretsManagerProjectByID(cmd, client, slugOrID)
	}
	return secretsManagerProjectBySlug(cmd, client, slugOrID).ProjectDetails
}

func secretsManagerProjectByID(cmd *cobra.Command, client *resty.Client, projectID string) api.ProjectDetails {
	project, err := api.CallGetProject(client, projectID)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, errorScope{ProjectID: projectID}, func(cause error) *util.CLIError {
			return errProjectNotFound(errorScope{ProjectID: projectID}, cause)
		}), "Unable to get the project")
	}
	if project.Type != "" && project.Type != secretManagerProjectType {
		exitWithError(cmd, errProjectTypeNotSupported(project.Name, project.Type))
	}
	return project
}

// secretsManagerProjectBySlug exits with project_not_found or project_type_not_supported rather than
// return a project the secrets-manager commands can't act on.
func secretsManagerProjectBySlug(cmd *cobra.Command, client *resty.Client, slug string) api.ProjectSettings {
	project, err := api.CallGetProjectSettingsBySlug(client, slug)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, errorScope{ProjectName: util.SuggestedValue(slug, "slug")}, func(cause error) *util.CLIError {
			return errProjectNotFound(errorScope{ProjectName: util.SuggestedValue(slug, "slug")}, cause)
		}), "Unable to get the project")
	}
	if project.Type != "" && project.Type != secretManagerProjectType {
		exitWithError(cmd, errProjectTypeNotSupported(project.Name, project.Type))
	}
	return project
}

func runProjectsDelete(cmd *cobra.Command, args []string) {
	slug := args[0]
	outputFormat := projectsOutputFormat(cmd)
	client := secretsManagerHTTPClient(cmd, "delete projects")

	project := secretsManagerProjectBySlug(cmd, client, slug)
	if project.HasDeleteProtection {
		exitWithError(cmd, errProjectDeleteProtected(project.Name))
	}

	if err := confirmDestructive(cmd, args, destructiveAction{
		Target:      "project " + quoted(slug, "slug"),
		Expected:    slug,
		Label:       "the project slug",
		Description: fmt.Sprintf("project %q (%s), with all of its environments and secrets, permanently", project.Name, util.SuggestedValue(slug, "slug")),
	}); err != nil {
		exitWithError(cmd, err)
	}

	deleted, err := api.CallDeleteProject(client, project.ID)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, errorScope{ProjectName: util.SuggestedValue(slug, "slug")}, func(cause error) *util.CLIError {
			return errProjectNotFound(errorScope{ProjectName: util.SuggestedValue(slug, "slug")}, cause)
		}), "Unable to delete the project")
	}

	if outputFormat != "" {
		printFormattedOutput(outputFormat, deleted)
	} else {
		printSuccessNotice(cmd, fmt.Sprintf("Permanently deleted project %s.", util.SanitizeDisplay(project.Name)))
		if linkedProjectID() == project.ID {
			printProjectsTip(cmd, "This directory is still linked to the deleted project. To link it to another one, run [infisical init].")
		}
	}

	Telemetry.CaptureEvent("cli-command:projects delete", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

// projectUpdate reads the change flags. A name or slug can't be empty, but an empty description clears it.
func projectUpdate(cmd *cobra.Command) (api.UpdateProjectRequest, *util.CLIError) {
	var request api.UpdateProjectRequest
	for _, field := range []struct {
		flag       string
		value      **string
		allowEmpty bool
	}{{"name", &request.Name, false}, {"slug", &request.Slug, false}, {"description", &request.Description, true}} {
		if !cmd.Flags().Changed(field.flag) {
			continue
		}
		value, _ := cmd.Flags().GetString(field.flag)
		value = strings.TrimSpace(value)
		if value == "" && !field.allowEmpty {
			return api.UpdateProjectRequest{}, errEmptyFlag(field.flag)
		}
		*field.value = &value
	}
	return request, nil
}

func runProjectsUpdate(cmd *cobra.Command, args []string) {
	outputFormat := projectsOutputFormat(cmd)
	request, invalid := projectUpdate(cmd)
	if invalid != nil {
		exitWithError(cmd, invalid)
	}
	if request.Name == nil && request.Slug == nil && request.Description == nil {
		exitWithError(cmd, errNothingToUpdate([]string{"name", "slug", "description"}))
	}

	client := secretsManagerHTTPClient(cmd, "update projects")
	project := secretsManagerProject(cmd, client, args[0])
	updated, err := api.CallUpdateProject(client, project.ID, request)
	if err != nil {
		scope := errorScope{ProjectName: project.Name}
		exitWithError(cmd, classifyAPIError(err, scope, func(cause error) *util.CLIError {
			return errProjectNotFound(scope, cause)
		}), "Unable to update the project")
	}

	if outputFormat != "" {
		printFormattedOutput(outputFormat, updated)
	} else {
		printSuccessNotice(cmd, fmt.Sprintf("Updated project %s", util.SanitizeDisplay(updated.Name)))
		printProjectDetails(updated)
	}

	Telemetry.CaptureEvent("cli-command:projects update", posthog.NewProperties().Set("bySlug", !isProjectID(args[0])).Set("version", util.CLI_VERSION))
}

// linkedProjectID is the project .infisical.yaml (or a legacy .infisical.json) links this directory
// to, or "" when there's none or it can't be read.
func linkedProjectID() string {
	configFile, err := util.FindWorkspaceConfigFile()
	if err != nil {
		return ""
	}
	workspaceFile, err := util.GetWorkSpaceFromFilePath(filepath.Dir(configFile))
	if err != nil {
		return ""
	}
	return workspaceFile.WorkspaceId
}

func runProjectsCreate(cmd *cobra.Command, args []string) {
	outputFormat := projectsOutputFormat(cmd)
	name, _ := cmd.Flags().GetString("name")
	name = strings.TrimSpace(name)
	if name == "" {
		exitWithError(cmd, errFlagRequired("name", "the name of the new project"))
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
		exitWithError(cmd, classifyAPIError(err, errorScope{}, nil), "Unable to create the project")
	}

	if outputFormat != "" {
		printFormattedOutput(outputFormat, project)
	} else {
		printSuccessNotice(cmd, fmt.Sprintf("Created project %s", util.SanitizeDisplay(project.Name)))
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
