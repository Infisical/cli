package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

// Error codes are a stable contract for scripts and agents: add new ones, never rename or remove
// one. Every code here is listed in the Errors section of CLI.md.
const (
	errCodeAuthRequired            = "auth_required"
	errCodePermissionDenied        = "permission_denied"
	errCodeProjectNotLinked        = "project_not_linked"
	errCodeProjectNotFound         = "project_not_found"
	errCodeProjectTypeNotSupported = "project_type_not_supported"
	errCodeEnvironmentNotFound     = "environment_not_found"
	errCodeSecretExists            = "secret_exists"
	errCodeSecretNotFound          = "secret_not_found"
	errCodeFolderNotFound          = "folder_not_found"
	errCodeNothingToUpdate         = "nothing_to_update"
	errCodeConfirmationRequired    = "confirmation_required"
	errCodeConfirmationDeclined    = "confirmation_declined"
)

var errorCodes = []string{
	errCodeAuthRequired, errCodePermissionDenied, errCodeProjectNotLinked, errCodeProjectNotFound,
	errCodeProjectTypeNotSupported, errCodeEnvironmentNotFound, errCodeSecretExists, errCodeSecretNotFound,
	errCodeFolderNotFound, errCodeNothingToUpdate, errCodeConfirmationRequired, errCodeConfirmationDeclined,
}

const secretsManagerPrefix = "infisical " + secretsManagerCommandName

// errorScope is what a command was working on, so an error can name it and suggest a command for
// the same project, environment and folder.
type errorScope struct {
	ProjectID   string
	ProjectName string
	Environment string
	SecretPath  string
}

func (s errorScope) projectLabel() string {
	if s.ProjectName != "" {
		return s.ProjectName
	}
	if s.ProjectID != "" {
		return s.ProjectID
	}
	return "the selected project"
}

// projectFlag repeats --projectId only when the command had one; otherwise the suggestion relies on
// the same fallbacks (INFISICAL_PROJECT_ID, .infisical.yaml) the failing command used.
func (s errorScope) projectFlag() string {
	if s.ProjectID == "" {
		return ""
	}
	return " --projectId " + util.SuggestedValue(s.ProjectID, "project-id")
}

func (s errorScope) secretScopeFlags() string {
	flags := ""
	if s.Environment != "" {
		flags += " --env " + util.SuggestedValue(s.Environment, "env")
	}
	if s.SecretPath != "" && s.SecretPath != "/" {
		flags += " --path " + util.SuggestedValue(s.SecretPath, "path")
	}
	return flags + s.projectFlag()
}

func listOf(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = fmt.Sprintf("%q", name)
	}
	return strings.Join(quoted, ", ")
}

func errAuthRequired(cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeAuthRequired, Cause: cause,
		Message: "You're not logged in, or your token is invalid or has expired.",
		Next:    []util.NextStep{{Purpose: "To log in", Command: "infisical login"}}}
}

func errPermissionDenied(serverMessage string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodePermissionDenied, Cause: cause,
		Message: fmt.Sprintf("You don't have permission to do this (%s). Ask a project admin for access.", strings.TrimSuffix(serverMessage, "."))}
}

func errProjectNotLinked() *util.CLIError {
	return &util.CLIError{Code: errCodeProjectNotLinked,
		Message: "No project is selected: this directory isn't linked to one and --projectId wasn't passed.",
		Next: []util.NextStep{
			{Purpose: "To link this directory to a project", Command: "infisical init"},
			{Purpose: "To find a project ID to pass with --projectId", Command: secretsManagerPrefix + " projects list"},
		}}
}

func errProjectNotFound(scope errorScope, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeProjectNotFound, Cause: cause,
		Message: fmt.Sprintf("Project %q doesn't exist, or you don't have access to it.", scope.projectLabel()),
		Next:    []util.NextStep{{Purpose: "To see the projects you can access", Command: secretsManagerPrefix + " projects list"}}}
}

func errProjectTypeNotSupported(projectName, projectType string) *util.CLIError {
	return &util.CLIError{Code: errCodeProjectTypeNotSupported,
		Message: fmt.Sprintf("%q is a %s project, and %s commands only work with Secrets Management projects.", projectName, projectType, secretsManagerCommandName),
		Next:    []util.NextStep{{Purpose: "To see your Secrets Management projects", Command: secretsManagerPrefix + " projects list"}}}
}

func errEnvironmentNotFound(slug string, scope errorScope, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeEnvironmentNotFound, Cause: cause,
		Message: fmt.Sprintf("Environment %q doesn't exist in project %q.", slug, scope.projectLabel()),
		Next: []util.NextStep{{Purpose: "To see the environments in this project",
			Command: secretsManagerPrefix + " environments get" + scope.projectFlag()}}}
}

func errSecretExists(names []string, scope errorScope) *util.CLIError {
	message := fmt.Sprintf("Secret %s already exists.", listOf(names))
	if len(names) > 1 {
		message = fmt.Sprintf("Secrets %s already exist.", listOf(names))
	}
	return &util.CLIError{Code: errCodeSecretExists, Message: message + " Nothing was written.",
		Next: []util.NextStep{{Purpose: "To change the value",
			Command: secretsManagerPrefix + " secrets update " + util.SuggestedValue(names[0], "name") + "=<value>" + scope.secretScopeFlags()}}}
}

func errSecretNotFound(names []string, scope errorScope) *util.CLIError {
	message := fmt.Sprintf("Secret %s doesn't exist.", listOf(names))
	if len(names) > 1 {
		message = fmt.Sprintf("Secrets %s don't exist.", listOf(names))
	}
	return &util.CLIError{Code: errCodeSecretNotFound, Message: message + " Nothing was written.",
		Next: []util.NextStep{{Purpose: "To create it",
			Command: secretsManagerPrefix + " secrets create " + util.SuggestedValue(names[0], "name") + "=<value>" + scope.secretScopeFlags()}}}
}

func errFolderNotFound(name string, scope errorScope) *util.CLIError {
	path := scope.SecretPath
	if path == "" {
		path = "/"
	}
	return &util.CLIError{Code: errCodeFolderNotFound,
		Message: fmt.Sprintf("Folder %q doesn't exist in %q.", name, path),
		Next: []util.NextStep{{Purpose: "To see the folders there",
			Command: secretsManagerPrefix + " folders get --path " + util.SuggestedValue(path, "path") + scope.secretScopeFlags()}}}
}

func errNothingToUpdate(flags []string) *util.CLIError {
	return &util.CLIError{Code: errCodeNothingToUpdate,
		Message: fmt.Sprintf("Nothing to update. Pass at least one of --%s.", strings.Join(flags, ", --"))}
}

func errConfirmationRequired(action destructiveAction, rerun string) *util.CLIError {
	return &util.CLIError{Code: errCodeConfirmationRequired,
		Message: fmt.Sprintf("Deleting %s %q needs confirmation, and there's no terminal to ask. Nothing was deleted.", action.Kind, action.Slug),
		Next:    []util.NextStep{{Purpose: "To delete it without asking", Command: rerun}}}
}

func errConfirmationDeclined(action destructiveAction) *util.CLIError {
	return &util.CLIError{Code: errCodeConfirmationDeclined,
		Message: fmt.Sprintf("Nothing was deleted: the confirmation didn't match the %s slug %q.", action.Kind, action.Slug)}
}

// classifyAPIError turns a backend error into a CLIError using only what is stable: the status code,
// the error names the backend guarantees (TokenError, PermissionDenied), and what the caller was
// looking up. It never reads the message text, which the backend can reword at any time. notFound
// builds the error for a 404 when the request had one subject (an environment by slug, a project by
// ID); pass nil when a 404 could mean several things. Anything else is returned unchanged, so it
// still prints the way it did before.
func classifyAPIError(err error, notFound func(cause error) *util.CLIError) error {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	switch {
	case apiErr.StatusCode == 401:
		return errAuthRequired(err)
	case apiErr.StatusCode == 403 && apiErr.Name == "TokenError":
		// The backend reports every JWT problem (expired, malformed, bad signature) as a 403 TokenError.
		return errAuthRequired(err)
	case apiErr.StatusCode == 403 && apiErr.Name == "PermissionDenied":
		return errPermissionDenied(apiErr.ErrorMessage, err)
	case apiErr.StatusCode == 404 && notFound != nil:
		return notFound(err)
	}
	return err
}

// errorOutputFormat is the -o format a command's error should use: json or yaml, or "" for text.
func errorOutputFormat(cmd *cobra.Command) string {
	if f := cmd.Flags().Lookup("output"); f != nil && f.Changed {
		if format := strings.ToLower(f.Value.String()); format == util.OUTPUT_FORMAT_JSON || format == util.OUTPUT_FORMAT_YAML {
			return format
		}
	}
	return ""
}
