package cmd

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/go-resty/resty/v2"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// The backend's rule for a new folder name (isValidFolderName), checked before create and rename send
// anything. Lookups match the listed names exactly instead, so a folder created before the backend
// enforced the rule can still be read, renamed and deleted.
var folderNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func buildFoldersCmd() *cobra.Command {
	foldersCmd := &cobra.Command{
		Use:   "folders",
		Short: "List, inspect, create, update, and delete the folders of an environment",
		Example: `# List the folders at / in the dev environment of the project linked to this directory
infisical secrets-manager folders get

infisical secrets-manager folders create api --env prod --path /backend --projectId <project-id>
infisical secrets-manager folders delete api --env prod --path /backend --projectId <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	getCmd := &cobra.Command{
		Use:   "get [name]",
		Short: "List the folders at a path, or show one",
		Example: `infisical secrets-manager folders get --env prod --path /backend
infisical secrets-manager folders get api --env prod --path /backend -o json`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run:                   runFoldersManagerGet,
	}
	addFoldersScopeFlags(getCmd, false)
	addFoldersCommonFlags(getCmd, "Get folders", "The output to format the folders in")
	foldersCmd.AddCommand(getCmd)

	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a folder",
		Example: `infisical secrets-manager folders create api --env prod --path /backend

# Missing parent folders in --path are created too
infisical secrets-manager folders create api --path /backend/services --description "Public API"`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runFoldersManagerCreate,
	}
	createCmd.Flags().String("description", "", "Description of the folder")
	addFoldersScopeFlags(createCmd, false)
	addFoldersCommonFlags(createCmd, "Create the folder", "The output to format the created folder in")
	foldersCmd.AddCommand(createCmd)

	updateCmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Rename a folder or change its description",
		Example: `infisical secrets-manager folders update api --name public-api --env prod --path /backend
infisical secrets-manager folders update api --description "" --path /backend`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runFoldersManagerUpdate,
	}
	updateCmd.Flags().String("name", "", "New name of the folder")
	updateCmd.Flags().String("description", "", `New description of the folder. Pass "" to clear it`)
	addFoldersScopeFlags(updateCmd, false)
	addFoldersCommonFlags(updateCmd, "Update the folder", "The output to format the updated folder in")
	foldersCmd.AddCommand(updateCmd)

	deleteCmd := &cobra.Command{
		Use:                   "delete <name>",
		Short:                 "Delete a folder and everything inside it",
		Example:               `infisical secrets-manager folders delete api --env prod --path /backend --projectId <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runFoldersManagerDelete,
	}
	addConfirmFlags(deleteCmd)
	addFoldersScopeFlags(deleteCmd, true)
	addFoldersCommonFlags(deleteCmd, "Delete the folder", "The output to format the deleted folder in")
	foldersCmd.AddCommand(deleteCmd)

	return foldersCmd
}

func addFoldersScopeFlags(cmd *cobra.Command, explicitProject bool) {
	cmd.Flags().String("env", "dev", "Slug of the environment (falls back to INFISICAL_ENVIRONMENT, then .infisical.yaml or a legacy .infisical.json)")
	cmd.Flags().String("path", "/", "Path of the parent folder (falls back to INFISICAL_SECRET_PATH, then secrets-management.secret-path in .infisical.yaml)")
	if explicitProject {
		cmd.Flags().String("projectId", "", "ID of the project, required (a delete never uses INFISICAL_PROJECT_ID or .infisical.yaml)")
	} else {
		cmd.Flags().String("projectId", "", projectIDFallsBack+"; a service token uses its own project")
	}
}

func addFoldersCommonFlags(cmd *cobra.Command, action, outputDescription string) {
	cmd.Flags().String("token", "", action+" using a machine identity access token or a service token")
	addProjectsOutputFlag(cmd, outputDescription)
}

type foldersTarget struct {
	client       *resty.Client
	project      api.ProjectEnvironments
	environment  string
	path         string
	scope        errorScope
	outputFormat string
	folders      []api.Folder
}

// folderOutput is a folder in structured output. Path is the folder's own path, so it can be passed
// as --path to work inside it.
type folderOutput struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Environment string `json:"environment"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt,omitempty"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

func folderParentPath(value string) string {
	return path.Clean("/" + strings.TrimSpace(value))
}

func requireFolderName(cmd *cobra.Command, name, flag string) {
	if !folderNamePattern.MatchString(name) {
		exitWithError(cmd, errInvalidFolderName(name, flag))
	}
}

// A delete passes explicitProject: it never falls back to INFISICAL_PROJECT_ID or .infisical.yaml.
func loadFoldersTarget(cmd *cobra.Command, explicitProject bool) foldersTarget {
	outputFormat := crudOutputFormat(cmd, "folders")

	var projectID string
	if explicitProject {
		if projectID, _ = cmd.Flags().GetString("projectId"); projectID == "" {
			exitWithError(cmd, errProjectRequired("a folder"))
		}
	} else {
		projectID = resolveProjectID(cmd)
	}

	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	// The folder routes act on whatever project the body names, but a service token is only valid for
	// its own, so the selection has to match it.
	if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER {
		projectID = serviceTokenWriteProject(cmd, token.Token, projectID)
	}
	if projectID == "" {
		exitWithError(cmd, errProjectNotLinked())
	}

	client := secretsManagerHTTPClient(cmd, "manage folders")
	project := secretsManagerProjectEnvironments(cmd, client, projectID)
	scope := errorScope{ProjectID: projectID, ProjectName: project.Name}

	environment := util.ResolveEnvironmentName(cmd)
	environments := environmentsTarget{project: project, scope: scope}
	if _, ok := environments.active(environment); !ok {
		if pending, ok := environments.pending(environment); ok {
			exitWithError(cmd, errEnvironmentPendingForFolders(environment, pending.DeleteAfter, scope))
		}
		exitWithError(cmd, errEnvironmentNotFound(environment, scope, nil))
	}
	scope.Environment = environment
	scope.SecretPath = folderParentPath(util.ResolveSecretPath(cmd))

	folders, err := api.CallListFolders(client, projectID, environment, scope.SecretPath)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, scope, nil), "Unable to get the folders")
	}

	return foldersTarget{
		client:       client,
		project:      project,
		environment:  environment,
		path:         scope.SecretPath,
		scope:        scope,
		outputFormat: outputFormat,
		folders:      folders,
	}
}

func (t foldersTarget) find(name string) (api.Folder, bool) {
	for _, folder := range t.folders {
		if folder.Name == name {
			return folder, true
		}
	}
	return api.Folder{}, false
}

func (t foldersTarget) existing(cmd *cobra.Command, name string) api.Folder {
	folder, ok := t.find(name)
	if !ok {
		exitWithError(cmd, errFolderNotFound(name, t.scope, nil))
	}
	return folder
}

func (t foldersTarget) output(folder api.Folder) folderOutput {
	return folderOutput{ID: folder.ID, Name: folder.Name, Path: path.Join(t.path, folder.Name), Environment: t.environment,
		Description: folder.Description, CreatedAt: folder.CreatedAt, UpdatedAt: folder.UpdatedAt}
}

func (t foldersTarget) where() string {
	return fmt.Sprintf("in the %s environment of project %q", util.SanitizeDisplay(t.environment), t.project.Name)
}

func (t foldersTarget) printFolders(folders []api.Folder) {
	rows := make([][3]string, 0, len(folders))
	for _, folder := range folders {
		rows = append(rows, [3]string{util.SanitizeDisplay(folder.Name), util.SanitizeDisplay(path.Join(t.path, folder.Name)), util.SanitizeDisplay(folder.ID)})
	}
	visualize.Table([3]string{"FOLDER NAME", "FOLDER PATH", "FOLDER ID"}, rows)
}

func (t foldersTarget) printFolder(cmd *cobra.Command, folder api.Folder, notice string) {
	if t.outputFormat != "" {
		printFormattedOutput(t.outputFormat, t.output(folder))
		return
	}
	if notice != "" {
		printSuccessNotice(cmd, notice)
	}
	t.printFolders([]api.Folder{folder})
}

func runFoldersManagerGet(cmd *cobra.Command, args []string) {
	target := loadFoldersTarget(cmd, false)

	if len(args) == 1 {
		target.printFolder(cmd, target.existing(cmd, args[0]), "")
		Telemetry.CaptureEvent("cli-command:folders get", posthog.NewProperties().Set("byName", true).Set("version", util.CLI_VERSION))
		return
	}

	switch {
	case target.outputFormat != "":
		listed := make([]folderOutput, 0, len(target.folders))
		for _, folder := range target.folders {
			listed = append(listed, target.output(folder))
		}
		printFormattedOutput(target.outputFormat, listed)
	case len(target.folders) == 0:
		printProjectsTip(cmd, fmt.Sprintf("There are no folders at %s %s. Create one with [infisical secrets-manager folders create <name> --path %s%s].",
			util.SanitizeDisplay(target.path), target.where(), util.SuggestedValue(target.path, "path"), target.scope.envFlag()+target.scope.projectFlag()))
	default:
		target.printFolders(target.folders)
	}
	Telemetry.CaptureEvent("cli-command:folders get", posthog.NewProperties().Set("folderCount", len(target.folders)).Set("version", util.CLI_VERSION))
}

func runFoldersManagerCreate(cmd *cobra.Command, args []string) {
	name := args[0]
	requireFolderName(cmd, name, "")
	target := loadFoldersTarget(cmd, false)
	if _, ok := target.find(name); ok {
		exitWithError(cmd, errFolderExists(name, target.scope))
	}

	request := api.CreateFolderRequest{ProjectID: target.project.ID, Environment: target.environment, Name: name, Path: target.path}
	if cmd.Flags().Changed("description") {
		description, _ := cmd.Flags().GetString("description")
		request.Description = &description
	}
	folder, err := api.CallCreateFolder(target.client, request)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, target.scope, nil), "Unable to create the folder")
	}

	target.printFolder(cmd, folder, fmt.Sprintf("Created folder %s %s", util.SanitizeDisplay(path.Join(target.path, folder.Name)), target.where()))
	Telemetry.CaptureEvent("cli-command:folders create", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

// folderUpdate reads the change flags. An explicitly empty --name is an error, while an empty
// --description clears it.
func folderUpdate(cmd *cobra.Command) (newName, description *string) {
	if cmd.Flags().Changed("name") {
		value, _ := cmd.Flags().GetString("name")
		value = strings.TrimSpace(value)
		if value == "" {
			exitWithError(cmd, errEmptyFlag("name"))
		}
		requireFolderName(cmd, value, "name")
		newName = &value
	}
	if cmd.Flags().Changed("description") {
		value, _ := cmd.Flags().GetString("description")
		description = &value
	}
	return newName, description
}

func runFoldersManagerUpdate(cmd *cobra.Command, args []string) {
	name := args[0]
	newName, description := folderUpdate(cmd)
	if newName == nil && description == nil {
		exitWithError(cmd, errNothingToUpdate([]string{"name", "description"}))
	}

	target := loadFoldersTarget(cmd, false)
	existing := target.existing(cmd, name)
	request := api.UpdateFolderRequest{ProjectID: target.project.ID, Environment: target.environment, Name: existing.Name, Path: target.path, Description: description}
	if newName != nil {
		if *newName != existing.Name {
			if _, taken := target.find(*newName); taken {
				exitWithError(cmd, errFolderExists(*newName, target.scope))
			}
		}
		request.Name = *newName
	}

	folder, err := api.CallUpdateFolder(target.client, existing.ID, request)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, target.scope, func(cause error) *util.CLIError {
			return errFolderNotFound(name, target.scope, cause)
		}), "Unable to update the folder")
	}

	target.printFolder(cmd, folder, fmt.Sprintf("Updated folder %s %s", util.SanitizeDisplay(path.Join(target.path, folder.Name)), target.where()))
	Telemetry.CaptureEvent("cli-command:folders update", posthog.NewProperties().Set("renamed", newName != nil && *newName != existing.Name).Set("version", util.CLI_VERSION))
}

func runFoldersManagerDelete(cmd *cobra.Command, args []string) {
	name := args[0]
	target := loadFoldersTarget(cmd, true)
	existing := target.existing(cmd, name)

	folderPath := path.Join(target.path, existing.Name)
	description := fmt.Sprintf("folder %s %s, with every secret, dynamic secret and folder inside it", util.SuggestedValue(folderPath, "path"), target.where())
	if err := confirmDestructive(cmd, args, destructiveAction{
		Target:      "folder " + quoted(name, "name"),
		Expected:    name,
		Label:       "the folder name",
		Description: description,
		Scope:       []scopeFlag{{"env", target.environment}, {"path", target.path}, {"projectId", target.project.ID}},
	}); err != nil {
		exitWithError(cmd, err)
	}

	// The confirmation names everything inside the folder, so the delete removes it all, as the legacy
	// secrets folders delete does. The backend would otherwise refuse a folder that isn't empty.
	folder, err := api.CallDeleteFolder(target.client, existing.ID, api.DeleteFolderRequest{
		ProjectID: target.project.ID, Environment: target.environment, Path: target.path, ForceDelete: true,
	})
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, target.scope, func(cause error) *util.CLIError {
			return errFolderNotFound(name, target.scope, cause)
		}), "Unable to delete the folder")
	}

	if target.outputFormat != "" {
		printFormattedOutput(target.outputFormat, target.output(folder))
	} else {
		printSuccessNotice(cmd, fmt.Sprintf("Deleted folder %s %s.", util.SanitizeDisplay(folderPath), target.where()))
	}
	Telemetry.CaptureEvent("cli-command:folders delete", posthog.NewProperties().Set("version", util.CLI_VERSION))
}
