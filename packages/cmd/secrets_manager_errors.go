package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
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
	errCodeEnvironmentExists       = "environment_exists"
	errCodeEnvironmentPending      = "environment_pending_deletion"
	errCodeProjectRequired         = "project_required"
	errCodeInvalidFlagValue        = "invalid_flag_value"
	errCodeInvalidArgument         = "invalid_argument"
	errCodeServiceTokenUnsupported = "service_token_not_supported"
	errCodeTokenProjectMismatch    = "token_project_mismatch"
	errCodeProjectConfigInvalid    = "project_config_invalid"
	errCodeProjectDeleteProtected  = "project_delete_protected"
	errCodeSecretExists            = "secret_exists"
	errCodeSecretNotFound          = "secret_not_found"
	errCodeFolderNotFound          = "folder_not_found"
	errCodeFolderExists            = "folder_exists"
	errCodeNothingToUpdate         = "nothing_to_update"
	errCodeConfirmationRequired    = "confirmation_required"
	errCodeConfirmationDeclined    = "confirmation_declined"
)

var errorCodes = []string{
	errCodeAuthRequired, errCodePermissionDenied, errCodeProjectNotLinked, errCodeProjectNotFound,
	errCodeProjectTypeNotSupported, errCodeEnvironmentNotFound, errCodeSecretExists, errCodeSecretNotFound,
	errCodeFolderNotFound, errCodeNothingToUpdate, errCodeConfirmationRequired, errCodeConfirmationDeclined,
	errCodeEnvironmentExists, errCodeEnvironmentPending, errCodeProjectRequired, errCodeInvalidFlagValue,
	errCodeProjectDeleteProtected, errCodeInvalidArgument, errCodeServiceTokenUnsupported,
	errCodeProjectConfigInvalid, errCodeTokenProjectMismatch, errCodeFolderExists,
	errCodeAccessBundleRequired, errCodeInvalidAccessBundle, errCodeInvalidProjectID,
}

const secretsManagerPrefix = "infisical " + secretsManagerCommandName

// errorScope is what a command was working on, so an error can name it and suggest a command for
// the same project, environment and folder.
type errorScope struct {
	ProjectID   string
	ProjectName string
	Environment string
	SecretPath  string
	SecretType  string
}

func (s errorScope) projectLabel() string {
	if s.ProjectName != "" {
		return s.ProjectName
	}
	if s.ProjectID != "" {
		return util.SuggestedValue(s.ProjectID, "project-id")
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

func (s errorScope) envFlag() string {
	if s.Environment == "" {
		return ""
	}
	return " --env " + util.SuggestedValue(s.Environment, "env")
}

// secretScopeFlags repeats the folder even when it is /, because INFISICAL_SECRET_PATH or
// .infisical.yaml would otherwise choose it when the suggestion runs.
func (s errorScope) secretScopeFlags() string {
	path := ""
	if s.SecretPath != "" {
		path = " --path " + util.SuggestedValue(s.SecretPath, "path")
	}
	secretType := ""
	if s.SecretType == util.SECRET_TYPE_PERSONAL {
		secretType = " --type " + util.SECRET_TYPE_PERSONAL
	}
	return s.envFlag() + path + secretType + s.projectFlag()
}

// firstSecretName is the name a suggestion uses; constructors are always given at least one, but an
// empty list must not panic.
func firstSecretName(names []string) string {
	if len(names) == 0 {
		return "<name>"
	}
	return util.SuggestedValue(names[0], "name")
}

// quoted is how a message names something the user typed: quoted when it is a safe identifier, and
// <kind> otherwise, so a credential pasted in the wrong place never reaches a message, a log, or an
// agent's transcript.
func quoted(value, kind string) string {
	if shown := util.SuggestedValue(value, kind); shown != value {
		return shown
	}
	return strconv.Quote(value)
}

func listOf(names []string) string {
	shown := make([]string, len(names))
	for i, name := range names {
		shown[i] = quoted(name, "name")
	}
	return strings.Join(shown, ", ")
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
			{Purpose: "To find a project ID to pass with --projectId", Command: secretsManagerPrefix + " projects get"},
		}}
}

func errProjectNotFound(scope errorScope, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeProjectNotFound, Cause: cause,
		Message: fmt.Sprintf("Project %q doesn't exist, or you don't have access to it.", scope.projectLabel()),
		Next:    []util.NextStep{{Purpose: "To see the projects you can access", Command: secretsManagerPrefix + " projects get"}}}
}

func errProjectTypeNotSupported(projectName, projectType string) *util.CLIError {
	return &util.CLIError{Code: errCodeProjectTypeNotSupported,
		Message: fmt.Sprintf("%q is a %s project, and %s commands only work with Secrets Management projects.", projectName, projectType, secretsManagerCommandName),
		Next:    []util.NextStep{{Purpose: "To see your Secrets Management projects", Command: secretsManagerPrefix + " projects get"}}}
}

func errEnvironmentNotFound(slug string, scope errorScope, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeEnvironmentNotFound, Cause: cause,
		Message: fmt.Sprintf("Environment %s doesn't exist in project %q.", quoted(slug, "env"), scope.projectLabel()),
		Next: []util.NextStep{{Purpose: "To see the environments in this project",
			Command: secretsManagerPrefix + " environments get" + scope.projectFlag()}}}
}

func errEnvironmentExists(slug string, scope errorScope) *util.CLIError {
	return &util.CLIError{Code: errCodeEnvironmentExists,
		Message: fmt.Sprintf("Environment %s already exists in project %q. Nothing was written.", quoted(slug, "env"), scope.projectLabel()),
		Next: []util.NextStep{{Purpose: "To see it",
			Command: secretsManagerPrefix + " environments get " + util.SuggestedValue(slug, "slug") + scope.projectFlag()}}}
}

// errEnvironmentPending is for a slug held by an environment that is soft-deleted but not yet gone:
// it can't be used, created again, or deleted again without --force until deleteAfter.
func errEnvironmentPending(slug, deleteAfter string, scope errorScope) *util.CLIError {
	until := ""
	if day := formatDay(deleteAfter); day != "" {
		until = " until " + day
	}
	return &util.CLIError{Code: errCodeEnvironmentPending,
		Message: fmt.Sprintf("Environment %s in project %q is pending deletion%s, and keeps its slug until then.", quoted(slug, "env"), scope.projectLabel(), until),
		Next: []util.NextStep{{Purpose: "To delete it now and free the slug",
			Command: secretsManagerPrefix + " environments delete " + util.SuggestedValue(slug, "slug") + " --force" + scope.projectFlag()}}}
}

func errEnvironmentPendingForFolders(slug, deleteAfter string, scope errorScope) *util.CLIError {
	until := ""
	if day := formatDay(deleteAfter); day != "" {
		until = " until " + day
	}
	return &util.CLIError{Code: errCodeEnvironmentPending,
		Message: fmt.Sprintf("Environment %s in project %q is pending deletion%s, so its folders can't be used.", quoted(slug, "env"), scope.projectLabel(), until),
		Next: []util.NextStep{{Purpose: "To see the active environments",
			Command: secretsManagerPrefix + " environments get" + scope.projectFlag()}}}
}

// errProjectRequired is for a destructive command run without --projectId: it never falls back to
// INFISICAL_PROJECT_ID or the workspace file (see CLI.md).
func errProjectRequired(what string) *util.CLIError {
	return &util.CLIError{Code: errCodeProjectRequired,
		Message: fmt.Sprintf("Deleting %s needs --projectId: a delete never uses %s or the project linked to this directory.", what, util.INFISICAL_PROJECT_ID_NAME),
		Next:    []util.NextStep{{Purpose: "To find the project ID", Command: secretsManagerPrefix + " projects get"}}}
}

func errEmptyProjectID() *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: "--projectId can't be empty: pass a project ID, or leave it out to list your projects."}
}

func errEmptyFlag(flag string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--%s can't be empty: pass a value, or leave out --%s to keep the current one.", flag, flag)}
}

func errFlagRequired(flag, value string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--%s is required: pass %s.", flag, value)}
}

func errInvalidSecretType(secretType string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: fmt.Sprintf("--type must be %q or %q, not %s.", util.SECRET_TYPE_SHARED, util.SECRET_TYPE_PERSONAL, quoted(secretType, "type"))}
}

// errServiceTokenUnsupported names what the command can't do with a service token, the alternative
// that works, and the command for it.
func errServiceTokenUnsupported(what, alternative string, next util.NextStep) *util.CLIError {
	return &util.CLIError{Code: errCodeServiceTokenUnsupported,
		Message: fmt.Sprintf("Service tokens can't %s: %s.", what, alternative),
		Next:    []util.NextStep{next}}
}

func errProjectConfigInvalid(path string, cause error) *util.CLIError {
	return &util.CLIError{Code: errCodeProjectConfigInvalid, Cause: cause,
		Message: fmt.Sprintf("The project config at %s can't be read (%s).", util.SanitizeDisplay(path), util.SanitizeDisplay(cause.Error())),
		Next:    []util.NextStep{{Purpose: "To link this directory to a project again", Command: "infisical init"}}}
}

func errSecretRepeated(name string) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidArgument,
		Message: fmt.Sprintf("Secret %s is given more than once: pass each secret once. Nothing was written.", quoted(name, "name"))}
}

func errSecretAssignmentInvalid(position int) *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidArgument,
		Message: fmt.Sprintf("Argument %d isn't in NAME=value form: pass each secret as NAME=value or NAME=@filepath. Nothing was written.", position)}
}

// errSecretArgumentInvalid names the secret by its key, never by its value, which may be a credential.
func errSecretArgumentInvalid(invalid *util.SecretArgInvalid) *util.CLIError {
	var problem string
	switch invalid.Problem {
	case util.SecretArgNoName:
		problem = fmt.Sprintf("Argument %d has no secret name: pass it as NAME=value.", invalid.Position)
	case util.SecretArgNoValue:
		problem = fmt.Sprintf("Secret %s has no value: pass it as NAME=value or NAME=@filepath.", quoted(invalid.Key, "name"))
	default:
		problem = fmt.Sprintf("Secret name %s starts with a number: secret names must start with a letter or an underscore.", quoted(invalid.Key, "name"))
	}
	return &util.CLIError{Code: errCodeInvalidArgument, Message: problem + " Nothing was written."}
}

func errSecretFileInvalid(badFile *util.SecretFileInvalid) *util.CLIError {
	file := quoted(badFile.File, "file")
	var problem string
	switch badFile.Problem {
	case util.SecretFileNotFound:
		problem = fmt.Sprintf("--file %s doesn't exist.", file)
	case util.SecretFileUnreadable:
		problem = fmt.Sprintf("--file %s can't be read.", file)
	case util.SecretFileUnparsable:
		problem = fmt.Sprintf("--file %s isn't a valid .env or YAML file.", file)
	case util.SecretFileInvalidKey:
		problem = fmt.Sprintf("Secret name %s in --file %s isn't valid: names can't be empty, start with a number, or contain spaces.", quoted(badFile.Key, "name"), file)
	case util.SecretFileEmptyValue:
		problem = fmt.Sprintf("Secret %s in --file %s has no value.", quoted(badFile.Key, "name"), file)
	default:
		problem = fmt.Sprintf("--file %s has no secrets.", file)
	}
	return &util.CLIError{Code: errCodeInvalidFlagValue, Message: problem + " Nothing was written."}
}

func errServiceTokenProjectMismatch(selected, tokenProject string) *util.CLIError {
	return &util.CLIError{Code: errCodeTokenProjectMismatch,
		Message: fmt.Sprintf("The service token is for project %s, not the selected project %s. Nothing was written: use a token for %s, or pass --projectId %s.",
			util.SuggestedValue(tokenProject, "token-project-id"), util.SuggestedValue(selected, "project-id"),
			util.SuggestedValue(selected, "project-id"), util.SuggestedValue(tokenProject, "token-project-id"))}
}

func errProjectSlugAndID() *util.CLIError {
	return &util.CLIError{Code: errCodeInvalidFlagValue,
		Message: "Pass the project as the argument or with --projectId, not both."}
}

// Read from the project's settings, never from the backend's error message.
func errProjectDeleteProtected(name string) *util.CLIError {
	return &util.CLIError{Code: errCodeProjectDeleteProtected,
		Message: fmt.Sprintf("Project %q has delete protection on: turn it off in the project's settings in Infisical, then delete it again. Nothing was deleted.", name)}
}

func formatDay(timestamp string) string {
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return ""
	}
	return parsed.Local().Format("2006-01-02")
}

func errSecretExists(names []string, scope errorScope) *util.CLIError {
	message := fmt.Sprintf("Secret %s already exists.", listOf(names))
	switch {
	case len(names) == 0:
		message = "The secret already exists."
	case len(names) > 1:
		message = fmt.Sprintf("Secrets %s already exist.", listOf(names))
	}
	return &util.CLIError{Code: errCodeSecretExists, Message: message + " Nothing was written.",
		Next: []util.NextStep{{Purpose: "To change the value",
			Command: secretsManagerPrefix + " secrets update " + firstSecretName(names) + "=<value>" + scope.secretScopeFlags()}}}
}

func errSecretNotFound(names []string, scope errorScope) *util.CLIError {
	message := fmt.Sprintf("Secret %s doesn't exist.", listOf(names))
	switch {
	case len(names) == 0:
		message = "The secret doesn't exist."
	case len(names) > 1:
		message = fmt.Sprintf("Secrets %s don't exist.", listOf(names))
	}
	return &util.CLIError{Code: errCodeSecretNotFound, Message: message + " Nothing was written.",
		Next: []util.NextStep{{Purpose: "To create it",
			Command: secretsManagerPrefix + " secrets create " + firstSecretName(names) + "=<value>" + scope.secretScopeFlags()}}}
}

func errFolderNotFound(name string, scope errorScope, cause error) *util.CLIError {
	path := scope.SecretPath
	if path == "" {
		path = "/"
	}
	return &util.CLIError{Code: errCodeFolderNotFound, Cause: cause,
		Message: fmt.Sprintf("Folder %s doesn't exist in %s.", quoted(name, "name"), quoted(path, "path")),
		Next: []util.NextStep{{Purpose: "To see the folders there",
			Command: secretsManagerPrefix + " folders get --path " + util.SuggestedValue(path, "path") + scope.envFlag() + scope.projectFlag()}}}
}

func errFolderExists(name string, scope errorScope) *util.CLIError {
	path := scope.SecretPath
	if path == "" {
		path = "/"
	}
	return &util.CLIError{Code: errCodeFolderExists,
		Message: fmt.Sprintf("Folder %s already exists in %s. Nothing was written.", quoted(name, "name"), quoted(path, "path")),
		Next: []util.NextStep{{Purpose: "To see it",
			Command: secretsManagerPrefix + " folders get " + util.SuggestedValue(name, "name") + " --path " + util.SuggestedValue(path, "path") + scope.envFlag() + scope.projectFlag()}}}
}

// errInvalidFolderName is for a name the backend would refuse. flag is "" for the positional name.
func errInvalidFolderName(name, flag string) *util.CLIError {
	code, subject := errCodeInvalidArgument, "Folder name "+quoted(name, "name")
	if flag != "" {
		code, subject = errCodeInvalidFlagValue, "--"+flag+" "+quoted(name, "name")
	}
	return &util.CLIError{Code: code,
		Message: subject + " isn't a valid folder name: use only letters, numbers, dashes and underscores, and name a nested folder's parent with --path. Nothing was sent."}
}

func errNothingToUpdate(flags []string) *util.CLIError {
	return &util.CLIError{Code: errCodeNothingToUpdate,
		Message: fmt.Sprintf("Nothing to update. Pass at least one of --%s.", strings.Join(flags, ", --"))}
}

func errConfirmationRequired(action destructiveAction, rerun string) *util.CLIError {
	return &util.CLIError{Code: errCodeConfirmationRequired,
		Message: fmt.Sprintf("Deleting %s needs confirmation, and there's no terminal to ask. Nothing was deleted.", action.Target),
		Next:    []util.NextStep{{Purpose: "To delete it without asking", Command: rerun}}}
}

// errConfirmedTargetChanged is for a delete whose environment, path or project resolved differently
// after the question was answered than when it was asked. before is empty when the target can no longer
// be resolved at all.
func errConfirmedTargetChanged(action destructiveAction, before, after scopeFlag) *util.CLIError {
	message := fmt.Sprintf("Nothing was deleted: the target of the delete of %s changed while you were confirming. Run the command again.", action.Target)
	if before.Name != "" {
		message = fmt.Sprintf("Nothing was deleted: --%s changed from %s to %s while you were confirming the delete of %s. Run the command again.",
			before.Name, quoted(before.Value, before.Name), quoted(after.Value, after.Name), action.Target)
	}
	return &util.CLIError{Code: errCodeConfirmationDeclined, Message: message}
}

func errConfirmationDeclined(action destructiveAction) *util.CLIError {
	return &util.CLIError{Code: errCodeConfirmationDeclined,
		Message: fmt.Sprintf("Nothing was deleted: the confirmation didn't match %s %s.", action.Label, quoted(action.Expected, "value"))}
}

// classifyAPIError turns a backend error into a CLIError using only what is stable: the status code,
// the error names the backend guarantees (TokenError, PermissionDenied, ProjectMembershipNotFound),
// and what the caller was looking up. It never reads the message text, which the backend can reword at
// any time. project names the project for ProjectMembershipNotFound, which reports it as
// project_not_found instead of echoing the project's ID back to someone who isn't a member. notFound
// builds the error for a 404 when the request had one subject (an environment by slug, a project by
// ID); pass nil when a 404 could mean several things. Anything else is returned unchanged, so it
// still prints the way it did before.
func classifyAPIError(err error, project errorScope, notFound func(cause error) *util.CLIError) error {
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
	case apiErr.StatusCode == 403 && apiErr.Name == "ProjectMembershipNotFound":
		return errProjectNotFound(project, err)
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

// Swapped out in tests, so a test can see a command stop without the test binary exiting.
var exitProcess = os.Exit

// exitWithError prints err and exits 1: a *util.CLIError in the CLI.md format, anything else the way
// util.HandleError always has, with messages.
func exitWithError(cmd *cobra.Command, err error, messages ...string) {
	var cliErr *util.CLIError
	if errors.As(err, &cliErr) {
		// The text format has no room for the request ID, which support asks for.
		var apiErr *api.APIError
		if errors.As(cliErr.Cause, &apiErr) && apiErr.ReqId != "" {
			log.Debug().Msgf("request ID: %s", util.SanitizeDisplay(apiErr.ReqId))
		}
		util.WriteCLIError(util.GetStderrWriter(), cliErr, errorOutputFormat(cmd))
		exitProcess(1)
		return
	}
	util.HandleError(err, messages...)
}
