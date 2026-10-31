/*
Copyright (c) 2026 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/go-resty/resty/v2"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

// buildEnvironmentsCmd builds the `infisical secrets-manager environments` command tree.
func buildEnvironmentsCmd() *cobra.Command {
	environmentsCmd := &cobra.Command{
		Use:     "environments",
		Aliases: []string{"environment"},
		Short:   "List, inspect, create, update, and delete the environments of a project",
		Example: `# List the environments of the project linked to this directory
infisical secrets-manager environments get

infisical secrets-manager environments create qa --projectId <project-id>
infisical secrets-manager environments delete qa --projectId <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	getCmd := &cobra.Command{
		Use:   "get [slug]",
		Short: "List the environments of a project, or show one",
		Example: `infisical secrets-manager environments get --projectId <project-id>
infisical secrets-manager environments get staging --projectId <project-id> -o json`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MaximumNArgs(1),
		Run:                   runEnvironmentsGet,
		Annotations:           serviceTokenUnsupported,
	}
	addEnvironmentsProjectFlag(getCmd)
	addEnvironmentsCommonFlags(getCmd, "Get environments", "The output to format the environments in")
	environmentsCmd.AddCommand(getCmd)

	createCmd := &cobra.Command{
		Use:   "create <slug>",
		Short: "Create an environment",
		Example: `infisical secrets-manager environments create qa --projectId <project-id>

# With a display name
infisical secrets-manager environments create qa --name "Quality Assurance" --projectId <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runEnvironmentsCreate,
		Annotations:           serviceTokenUnsupported,
	}
	createCmd.Flags().String("name", "", "Display name of the environment (defaults to the slug)")
	addEnvironmentsProjectFlag(createCmd)
	addEnvironmentsCommonFlags(createCmd, "Create the environment", "The output to format the created environment in")
	environmentsCmd.AddCommand(createCmd)

	updateCmd := &cobra.Command{
		Use:   "update <slug>",
		Short: "Change an environment's name or slug",
		Example: `infisical secrets-manager environments update qa --name "Quality Assurance" --projectId <project-id>
infisical secrets-manager environments update qa --slug testing --projectId <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runEnvironmentsUpdate,
		Annotations:           serviceTokenUnsupported,
	}
	updateCmd.Flags().String("name", "", "New display name")
	updateCmd.Flags().String("slug", "", "New slug")
	addEnvironmentsProjectFlag(updateCmd)
	addEnvironmentsCommonFlags(updateCmd, "Update the environment", "The output to format the updated environment in")
	environmentsCmd.AddCommand(updateCmd)

	deleteCmd := &cobra.Command{
		Use:   "delete <slug>",
		Short: "Delete an environment and all of its secrets",
		Example: `infisical secrets-manager environments delete qa --projectId <project-id>

# Delete for good now, skipping the grace period (also frees the slug of one pending deletion)
infisical secrets-manager environments delete qa --force --projectId <project-id>`,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run:                   runEnvironmentsDelete,
		Annotations:           serviceTokenUnsupported,
	}
	deleteCmd.Flags().String("projectId", "", "ID of the project, required (a delete never uses INFISICAL_PROJECT_ID or .infisical.yaml)")
	deleteCmd.Flags().Bool("force", false, "Delete for good now instead of after the grace period, including an environment already pending deletion")
	addConfirmFlags(deleteCmd)
	addEnvironmentsCommonFlags(deleteCmd, "Delete the environment", "The output to format the deleted environment in")
	environmentsCmd.AddCommand(deleteCmd)

	return environmentsCmd
}

func addEnvironmentsProjectFlag(cmd *cobra.Command) {
	cmd.Flags().String("projectId", "", "ID of the project (falls back to INFISICAL_PROJECT_ID, then .infisical.yaml or a legacy .infisical.json)")
}

func addEnvironmentsCommonFlags(cmd *cobra.Command, action, outputDescription string) {
	cmd.Flags().String("token", "", action+" using a machine identity access token")
	addProjectsOutputFlag(cmd, outputDescription)
}

// environmentsTarget is what every environments command starts from: the project, with its active
// environments and those pending deletion, and a client to act on it.
type environmentsTarget struct {
	client       *resty.Client
	project      api.ProjectEnvironments
	scope        errorScope
	outputFormat string
}

// loadEnvironmentsTarget resolves and fetches the project. With explicitProject, only --projectId
// counts, as for a delete.
func loadEnvironmentsTarget(cmd *cobra.Command, explicitProject bool) environmentsTarget {
	outputFormat := crudOutputFormat(cmd, "environments")

	var projectID string
	if explicitProject {
		projectID, _ = cmd.Flags().GetString("projectId")
		if projectID == "" {
			exitWithError(cmd, errProjectRequired("an environment"))
		}
	} else if projectID = resolveProjectID(cmd); projectID == "" {
		exitWithError(cmd, errProjectNotLinked())
	}

	client := secretsManagerHTTPClient(cmd, "manage environments")
	project, err := api.CallGetProjectEnvironments(client, projectID)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, func(cause error) *util.CLIError {
			return errProjectNotFound(errorScope{ProjectID: projectID}, cause)
		}), "Unable to get the project")
	}
	if project.Type != "" && project.Type != secretManagerProjectType {
		exitWithError(cmd, errProjectTypeNotSupported(project.Name, project.Type))
	}

	return environmentsTarget{
		client:       client,
		project:      project,
		scope:        errorScope{ProjectID: projectID, ProjectName: project.Name},
		outputFormat: outputFormat,
	}
}

func (t environmentsTarget) active(slug string) (api.ProjectEnvironment, bool) {
	for _, environment := range t.project.Environments {
		if environment.Slug == slug {
			return environment, true
		}
	}
	return api.ProjectEnvironment{}, false
}

func (t environmentsTarget) pending(slug string) (api.DeletedEnvironment, bool) {
	for _, environment := range t.project.DeletedEnvironments {
		if environment.Slug == slug {
			return environment, true
		}
	}
	return api.DeletedEnvironment{}, false
}

// existing returns the active environment with slug, or exits with environment_pending_deletion or
// environment_not_found.
func (t environmentsTarget) existing(cmd *cobra.Command, slug string) api.ProjectEnvironment {
	if environment, ok := t.active(slug); ok {
		return environment
	}
	if environment, ok := t.pending(slug); ok {
		exitWithError(cmd, errEnvironmentPending(slug, environment.DeleteAfter, t.scope))
	}
	exitWithError(cmd, errEnvironmentNotFound(slug, t.scope, nil))
	return api.ProjectEnvironment{}
}

// requireFreeSlug exits when slug is taken by an active environment or held by one pending deletion.
func (t environmentsTarget) requireFreeSlug(cmd *cobra.Command, slug string) {
	if _, ok := t.active(slug); ok {
		exitWithError(cmd, errEnvironmentExists(slug, t.scope))
	}
	if environment, ok := t.pending(slug); ok {
		exitWithError(cmd, errEnvironmentPending(slug, environment.DeleteAfter, t.scope))
	}
}

func (t environmentsTarget) printEnvironment(environment api.Environment, success string) {
	if t.outputFormat != "" {
		printFormattedOutput(t.outputFormat, environment)
		return
	}
	if success != "" {
		util.PrintSuccessMessage(success)
	}
	visualize.PrintEnvironmentDetails(environment)
}

func runEnvironmentsGet(cmd *cobra.Command, args []string) {
	target := loadEnvironmentsTarget(cmd, false)

	if len(args) == 1 {
		slug := args[0]
		if environment, ok := target.pending(slug); ok {
			exitWithError(cmd, errEnvironmentPending(slug, environment.DeleteAfter, target.scope))
		}
		environment, err := api.CallGetEnvironmentBySlug(target.client, target.project.ID, slug)
		if err != nil {
			exitWithError(cmd, classifyAPIError(err, func(cause error) *util.CLIError {
				return errEnvironmentNotFound(slug, target.scope, cause)
			}), "Unable to get the environment")
		}
		target.printEnvironment(environment, "")
		Telemetry.CaptureEvent("cli-command:environments get", posthog.NewProperties().Set("version", util.CLI_VERSION))
		return
	}

	if target.outputFormat != "" {
		printFormattedOutput(target.outputFormat, target.project.Environments)
	} else if len(target.project.Environments) == 0 {
		printProjectsTip(cmd, fmt.Sprintf("Project %s has no environments. Create one with [infisical secrets-manager environments create <slug>].", util.SanitizeDisplay(target.project.Name)))
	} else {
		visualize.PrintProjectEnvironments(target.project.ProjectDetails)
	}
	if len(target.project.DeletedEnvironments) > 0 && target.outputFormat == "" {
		pending := make([]string, 0, len(target.project.DeletedEnvironments))
		for _, environment := range target.project.DeletedEnvironments {
			pending = append(pending, fmt.Sprintf("%s (until %s)", util.SanitizeDisplay(environment.Slug), formatDay(environment.DeleteAfter)))
		}
		printProjectsTip(cmd, "\nPending deletion: "+strings.Join(pending, ", "))
	}

	Telemetry.CaptureEvent("cli-command:environments get", posthog.NewProperties().Set("environmentCount", len(target.project.Environments)).Set("version", util.CLI_VERSION))
}

func runEnvironmentsCreate(cmd *cobra.Command, args []string) {
	slug := args[0]
	target := loadEnvironmentsTarget(cmd, false)
	target.requireFreeSlug(cmd, slug)

	request := api.CreateEnvironmentRequest{Slug: slug, Name: slug}
	if name, _ := cmd.Flags().GetString("name"); strings.TrimSpace(name) != "" {
		request.Name = strings.TrimSpace(name)
	}

	environment, err := api.CallCreateEnvironment(target.client, target.project.ID, request)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, nil), "Unable to create the environment")
	}

	target.printEnvironment(environment, fmt.Sprintf("Created environment %s in project %s", util.SanitizeDisplay(environment.Slug), util.SanitizeDisplay(target.project.Name)))
	Telemetry.CaptureEvent("cli-command:environments create", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

// environmentUpdate is the PATCH body for the flags that were passed, trimmed. An explicitly empty
// --name or --slug is an error, since Changed is true for "" and the backend would get a blank value.
func environmentUpdate(cmd *cobra.Command) (api.UpdateEnvironmentRequest, error) {
	var request api.UpdateEnvironmentRequest
	for _, field := range []struct {
		flag  string
		value **string
	}{{"name", &request.Name}, {"slug", &request.Slug}} {
		if !cmd.Flags().Changed(field.flag) {
			continue
		}
		value, _ := cmd.Flags().GetString(field.flag)
		value = strings.TrimSpace(value)
		if value == "" {
			return api.UpdateEnvironmentRequest{}, fmt.Errorf("--%s can't be empty", field.flag)
		}
		*field.value = &value
	}
	return request, nil
}

func runEnvironmentsUpdate(cmd *cobra.Command, args []string) {
	slug := args[0]
	request, err := environmentUpdate(cmd)
	if err != nil {
		util.HandleError(err)
	}
	if request.Name == nil && request.Slug == nil {
		exitWithError(cmd, errNothingToUpdate([]string{"name", "slug"}))
	}

	target := loadEnvironmentsTarget(cmd, false)
	existing := target.existing(cmd, slug)
	if request.Slug != nil && *request.Slug != slug {
		target.requireFreeSlug(cmd, *request.Slug)
	}

	environment, err := api.CallUpdateEnvironment(target.client, target.project.ID, existing.ID, request)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, func(cause error) *util.CLIError {
			return errEnvironmentNotFound(slug, target.scope, cause)
		}), "Unable to update the environment")
	}

	target.printEnvironment(environment, fmt.Sprintf("Updated environment %s", util.SanitizeDisplay(environment.Slug)))
	Telemetry.CaptureEvent("cli-command:environments update", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

func runEnvironmentsDelete(cmd *cobra.Command, args []string) {
	slug := args[0]
	force, _ := cmd.Flags().GetBool("force")
	target := loadEnvironmentsTarget(cmd, true)
	project := fmt.Sprintf("%q", target.project.Name)

	var environmentID, description string
	if active, ok := target.active(slug); ok {
		environmentID = active.ID
		description = fmt.Sprintf("environment %s from project %s, with all of its secrets", util.SuggestedValue(slug, "slug"), project)
		if force {
			description += ", for good and without a grace period"
		}
	} else if pending, ok := target.pending(slug); ok && force {
		environmentID = pending.ID
		description = fmt.Sprintf("environment %s, already pending deletion, from project %s for good", util.SuggestedValue(slug, "slug"), project)
	} else {
		target.existing(cmd, slug)
	}

	if err := confirmDestructive(cmd, args, destructiveAction{
		Target:      "environment " + quoted(slug, "env"),
		Expected:    slug,
		Label:       "the environment slug",
		Description: description,
	}); err != nil {
		exitWithError(cmd, err)
	}

	environment, err := api.CallDeleteEnvironment(target.client, target.project.ID, environmentID, force)
	if err != nil {
		exitWithError(cmd, classifyAPIError(err, func(cause error) *util.CLIError {
			return errEnvironmentNotFound(slug, target.scope, cause)
		}), "Unable to delete the environment")
	}

	if target.outputFormat != "" {
		printFormattedOutput(target.outputFormat, environment)
	} else if day := formatDay(environment.DeleteAfter); day != "" {
		util.PrintSuccessMessage(fmt.Sprintf("Deleted environment %s. It will be removed for good on %s.", util.SanitizeDisplay(slug), day))
		printProjectsTip(cmd, fmt.Sprintf("To remove it now and free its slug, run [infisical secrets-manager environments delete %s --force --projectId %s].",
			util.SuggestedValue(slug, "slug"), util.SuggestedValue(target.project.ID, "project-id")))
	} else {
		util.PrintSuccessMessage(fmt.Sprintf("Deleted environment %s for good.", util.SanitizeDisplay(slug)))
	}

	Telemetry.CaptureEvent("cli-command:environments delete", posthog.NewProperties().Set("hardDelete", force).Set("version", util.CLI_VERSION))
}
