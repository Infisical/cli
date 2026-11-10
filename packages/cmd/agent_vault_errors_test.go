package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func agentVaultConstructedErrors() []*util.CLIError {
	cause := errors.New("cause")
	return []*util.CLIError{
		errAgentVaultInvalidOutput("xml"),
		errAgentVaultAccessBundleRequired(),
		errAgentVaultEmptyAccessBundle(),
		errAgentVaultOneAccessBundle(),
		errAgentVaultInvalidAccessBundle("Coding Agent", agentVaultSourceFlag),
		errAgentVaultAccessBundleNotGranted("coding-agent", cause),
		errAgentVaultEmptyProjectID(),
		errAgentVaultProjectRequired(),
		errAgentVaultInvalidProjectID("my-project", "--project-id"),
		errAgentVaultProjectNotFound(agentVaultProject{ID: projectFromFlag, Source: "--project-id"}, cause),
		errAgentVaultProjectNotFound(agentVaultProject{ID: projectFromProjEnv, Source: util.INFISICAL_PROJECT_ID_NAME}, cause),
		errAgentVaultConnectEmptyFlag("--proxy", agentVaultProxyAddressEnv),
		errAgentVaultConnectSessionTokenRequired(),
		errAgentVaultConnectProxyRequired(),
		errAgentVaultConnectProxyUnreachable("10.0.0.5:17323", cause),
		errAgentVaultConnectProxyUntrusted("10.0.0.5:17323", nil),
		errAgentVaultConnectFingerprintMismatch("10.0.0.5:17323", "SHA256:AA"),
		errAgentVaultConnectNoServices(),
		errAgentVaultConnectServiceNotFound("nope", nil),
		classifyAgentVaultConnectError(agentvault.ErrProxyTooOld, "10.0.0.5:17323").(*util.CLIError),
		classifyAgentVaultConnectError(&agentvault.ProxyRefusedError{Status: 403, Message: "no"}, "10.0.0.5:17323").(*util.CLIError),
		errAgentVaultConnectSessionInvalid(cause),
		errAgentVaultConnectSessionUnknown("10.0.0.5:17323", "https://eu.infisical.com", cause),
		errAgentVaultConnectFingerprintsNotListed("10.0.0.5:17323", cause),
		errAgentVaultConnectInfisicalUnreachable("10.0.0.5:17323", "https://eu.infisical.com", cause),
		errAgentVaultConnectPortNeedsOneService(),
		errAgentVaultConnectInvalidPort(70000),
		errAgentVaultConnectLocalPort("analytics", 5432, cause),
		errAgentVaultConnectLocalPort("analytics", 0, cause),
		errAgentVaultConnectAllRefused(),
	}
}

// runAgentVaultSessionsCreateForTest runs `infisical agent-vault sessions create <args>` on a fresh command, with
// an identity token from the environment, against an API that answers every request with status and the error
// name apiName. setup runs after the environment is reset. It returns stderr, whether the command exited 1, and
// how many requests reached the API.
func runAgentVaultSessionsCreateForTest(t *testing.T, setup func(), status int, apiName string, args ...string) (stderr string, exited bool, requests int) {
	t.Helper()
	isolateAgentVaultProject(t)
	t.Setenv(agentVaultAccessBundleEnv, "")
	t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME, "")
	t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME, "")
	t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "")
	t.Setenv(util.INFISICAL_TOKEN_NAME, "identity-access-token")
	if setup != nil {
		setup()
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"statusCode":%d,"error":%q,"message":"anything","reqId":"req-1"}`, status, apiName)
	}))
	t.Cleanup(srv.Close)
	oldURL := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"

	errOut := captureStderr(t)
	oldExit, oldTelemetry := exitProcess, Telemetry
	exitProcess = func(int) { panic(exitCalled{}) }
	Telemetry = telemetry.NewTelemetry(false)
	t.Cleanup(func() { config.INFISICAL_URL, exitProcess, Telemetry = oldURL, oldExit, oldTelemetry })

	cmd := &cobra.Command{Use: "create", Run: runAgentVaultSessionsCreate}
	cmd.Flags().Bool("silent", false, "")
	cmd.Flags().String("project-id", "", "")
	cmd.Flags().StringArray("access-bundle", nil, "")
	cmd.Flags().String("ttl", "never", "")
	cmd.Flags().String("label", "", "")
	cmd.Flags().String("client-id", "", "")
	cmd.Flags().String("client-secret", "", "")
	cmd.Flags().StringP("output", "o", "", "")
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(exitCalled); !ok {
					panic(r)
				}
				exited = true
			}
		}()
		cmd.Run(cmd, cmd.Flags().Args())
	}()
	return errOut.String(), exited, requests
}

type cliErrorFields struct {
	Code    string   `json:"code" yaml:"code"`
	Message string   `json:"message" yaml:"message"`
	Next    []string `json:"next" yaml:"next"`
}

func decodeCLIError(t *testing.T, format, stderr string) cliErrorFields {
	t.Helper()
	var body struct {
		Error cliErrorFields `json:"error" yaml:"error"`
	}
	var err error
	if format == util.OUTPUT_FORMAT_JSON {
		err = json.Unmarshal([]byte(stderr), &body)
	} else {
		err = yaml.Unmarshal([]byte(stderr), &body)
	}
	if err != nil || body.Error.Code == "" {
		t.Fatalf("stderr is not a %s error (%v):\n%s", format, err, stderr)
	}
	return body.Error
}

func TestAgentVaultSessionsCreateErrorsAreStructured(t *testing.T) {
	withProject := func(args ...string) []string { return append(args, "--project-id", projectFromFlag) }
	cases := []struct {
		name    string
		args    []string
		setup   func()
		status  int
		apiName string
		code    string
		message string
	}{
		{name: "no access bundle", args: withProject(), code: errCodeAccessBundleRequired, message: agentVaultAccessBundleEnv},
		{name: "empty access bundle", args: withProject("--access-bundle", " "), code: errCodeInvalidFlagValue, message: "names no bundle"},
		{name: "two access bundles", args: withProject("--access-bundle", "a", "--access-bundle", "b"), code: errCodeInvalidFlagValue, message: "one access bundle"},
		{name: "invalid access bundle", args: withProject("--access-bundle", "Coding_Agent"), code: errCodeInvalidAccessBundle, message: `"Coding_Agent" from --access-bundle`},
		{name: "invalid access bundle from the environment", args: withProject(),
			setup: func() { t.Setenv(agentVaultAccessBundleEnv, "Coding_Agent") }, code: errCodeInvalidAccessBundle, message: "from " + agentVaultAccessBundleEnv},
		{name: "no project", args: []string{"--access-bundle", "coding-agent"}, code: errCodeProjectRequired, message: agentVaultProjectIDEnv},
		{name: "empty project", args: []string{"--access-bundle", "coding-agent", "--project-id", " "}, code: errCodeInvalidFlagValue, message: "--project-id was given but is empty"},
		{name: "not a project ID", args: []string{"--access-bundle", "coding-agent", "--project-id", "my-project"}, code: errCodeInvalidProjectID, message: `"my-project" from --project-id`},
		{name: "project 404", args: withProject("--access-bundle", "coding-agent"), status: 404, apiName: "NotFound", code: errCodeProjectNotFound, message: projectFromFlag},
		{name: "project 404 from INFISICAL_PROJECT_ID", args: []string{"--access-bundle", "coding-agent"},
			setup:  func() { t.Setenv(util.INFISICAL_PROJECT_ID_NAME, projectFromProjEnv) },
			status: 404, apiName: "NotFound", code: errCodeProjectNotFound, message: "may name a Secrets Management project"},
		{name: "not a member", args: withProject("--access-bundle", "coding-agent"), status: 403, apiName: "ProjectMembershipNotFound", code: errCodeProjectNotFound, message: "from --project-id doesn't exist"},
		{name: "access bundle not granted", args: withProject("--access-bundle", "coding-agent"), status: 400, apiName: "AccessBundleNotGranted",
			code: errCodeAccessBundleNotGranted, message: `Access bundle "coding-agent" isn't granted to you`},
		{name: "permission denied", args: withProject("--access-bundle", "coding-agent"), status: 403, apiName: "PermissionDenied", code: errCodePermissionDenied},
		{name: "token rejected", args: withProject("--access-bundle", "coding-agent"), status: 401, apiName: "UnauthorizedError", code: errCodeAuthRequired},
	}
	for _, format := range []string{util.OUTPUT_FORMAT_JSON, util.OUTPUT_FORMAT_YAML} {
		for _, c := range cases {
			t.Run(format+"/"+c.name, func(t *testing.T) {
				status := c.status
				if status == 0 {
					status = http.StatusInternalServerError
				}
				stderr, exited, requests := runAgentVaultSessionsCreateForTest(t, c.setup, status, c.apiName, append(c.args, "-o", format)...)
				if !exited {
					t.Fatalf("want an exit, got stderr=%s", stderr)
				}
				got := decodeCLIError(t, format, stderr)
				if got.Code != c.code || !strings.Contains(got.Message, c.message) {
					t.Fatalf("want %s containing %q, got %s %q", c.code, c.message, got.Code, got.Message)
				}
				if c.status == 0 && requests != 0 {
					t.Fatalf("a refused input should send nothing, sent %d requests", requests)
				}
			})
		}
	}
}

// An unknown -o value is the error being reported, so it can't pick the format: the error is text, and no
// session is minted whose token would go unprinted.
func TestAgentVaultSessionsCreateRefusesAnUnknownOutputAsText(t *testing.T) {
	stderr, exited, requests := runAgentVaultSessionsCreateForTest(t, nil, http.StatusInternalServerError, "",
		"--access-bundle", "coding-agent", "--project-id", projectFromFlag, "-o", "xml")
	if !exited || requests != 0 {
		t.Fatalf("exited=%v requests=%d", exited, requests)
	}
	if want := `--output must be json or yaml, not "xml": leave it out to print only the token.` + "\n"; stderr != want {
		t.Fatalf("got %q, want %q", stderr, want)
	}
}

func TestAgentVaultSessionsCreateTextErrorsKeepTheirMessage(t *testing.T) {
	stderr, exited, _ := runAgentVaultSessionsCreateForTest(t, nil, http.StatusInternalServerError, "", "--project-id", projectFromFlag)
	if want := "An access bundle is required: pass --access-bundle <name> or set " + agentVaultAccessBundleEnv + ".\n"; !exited || stderr != want {
		t.Fatalf("got %q, want %q", stderr, want)
	}
}

// A token pasted into --access-bundle or --project-id never reaches the error, in any format.
func TestAgentVaultSessionsCreateErrorsNeverRepeatAPastedToken(t *testing.T) {
	const token = "agv_Xq3vR8kLmN2pQ7sT1uW4yZ6aB9cD0eF5gH-jK_oPqRs"
	for _, args := range [][]string{
		{"--access-bundle", token, "--project-id", projectFromFlag},
		{"--access-bundle", "coding-agent", "--project-id", token},
	} {
		for _, format := range []string{"", util.OUTPUT_FORMAT_JSON, util.OUTPUT_FORMAT_YAML} {
			withFormat := args
			if format != "" {
				withFormat = append(append([]string{}, args...), "-o", format)
			}
			stderr, exited, _ := runAgentVaultSessionsCreateForTest(t, nil, http.StatusInternalServerError, "", withFormat...)
			if !exited || strings.Contains(stderr, token) || strings.Contains(stderr, "Xq3vR8") {
				t.Errorf("%v -o %s: got %q", args, format, stderr)
			}
		}
	}
}

// An older Infisical without the route answers 404 for it, which says nothing about the project.
func TestClassifyAgentVaultAPIErrorLeavesAMissingRouteAlone(t *testing.T) {
	project := agentVaultProject{ID: projectFromFlag, Source: "--project-id"}
	missingRoute := apiError(404, infisicalRouteMissingName, "Route POST:/api/v1/agent-vault/sessions not found")
	if got := classifyAgentVaultAPIError(missingRoute, project, "x"); got != missingRoute {
		t.Errorf("a missing route should print as before, got %v", got)
	}
	if got := classifyAgentVaultAPIError(apiError(404, infisicalRouteMissingName, "reworded"), project, "x"); got == nil || codeOf(got) != "" {
		t.Errorf("a missing route is told apart by its name, not its message, got %v", got)
	}
	if got := classifyAgentVaultAPIError(apiError(403, "ProjectMembershipNotFound", ""), project, "x"); strings.Contains(got.Error(), projectFromFlag) {
		t.Errorf("a non-member's error should not repeat the project ID, got %q", got.Error())
	}
	if got := classifyAgentVaultAPIError(apiError(400, "BadRequest", "No access bundle named 'x'"), project, "x"); codeOf(got) != "" {
		t.Errorf("a 400 without a stable name is told apart only by its message, so it keeps no code, got %v", got)
	}
	notGranted := classifyAgentVaultAPIError(apiError(400, "AccessBundleNotGranted", "No access bundle named 'x' is granted"), project, "x")
	if codeOf(notGranted) != errCodeAccessBundleNotGranted || strings.Contains(notGranted.Error(), "is granted") {
		t.Errorf("a 400 AccessBundleNotGranted should get its code and keep the server's message out, got %v", notGranted)
	}
}
