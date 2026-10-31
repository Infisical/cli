package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

const testEnvironmentID = "0a6c2f4e-1b3d-4e5f-8a9b-0c1d2e3f4a5b"
const testPendingID = "9f8e7d6c-5b4a-4f3e-8d2c-1b0a9f8e7d6c"

// fakeEnvironmentsAPI answers the routes the environments commands call, like the backend does, and
// records every request so a test can assert what was (and wasn't) sent.
type fakeEnvironmentsAPI struct {
	projectType string
	missing     bool // GET /v1/projects/:id is a 404
	mu          sync.Mutex
	requests    []string
}

func (f *fakeEnvironmentsAPI) serve(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		line := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/api")
		if r.URL.RawQuery != "" {
			line += "?" + r.URL.RawQuery
		}
		if len(body) > 0 {
			line += " " + string(body)
		}
		f.mu.Lock()
		f.requests = append(f.requests, line)
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		notFound := func() {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"NotFound","message":"not found","reqId":"req-test"}`))
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/"+testProjectID)
		switch {
		case r.Method == http.MethodGet && path == "":
			if f.missing {
				notFound()
				return
			}
			projectType := f.projectType
			if projectType == "" {
				projectType = secretManagerProjectType
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"project": map[string]any{
				"id": testProjectID, "name": "payments-api", "slug": "payments-api", "type": projectType,
				"environments": []map[string]string{
					{"id": "e1", "name": "Development", "slug": "dev"},
					{"id": testEnvironmentID, "name": "Staging", "slug": "staging"},
				},
				"deletedEnvironments": []map[string]string{
					{"id": testPendingID, "name": "QA", "slug": "qa", "deleteAfter": "2026-11-12T10:00:00.000Z"},
				},
			}})
		case r.Method == http.MethodGet && path == "/environments/slug/staging":
			_, _ = fmt.Fprintf(w, `{"environment":{"id":%q,"name":"Staging","slug":"staging","position":2,"projectId":%q}}`, testEnvironmentID, testProjectID)
		case r.Method == http.MethodGet:
			notFound()
		case r.Method == http.MethodDelete:
			_, _ = fmt.Fprintf(w, `{"environment":{"id":"x","name":"n","slug":"s","position":1,"projectId":%q}}`, testProjectID)
		default:
			_, _ = fmt.Fprintf(w, `{"environment":{"id":"new","name":"n","slug":"s","position":3,"projectId":%q}}`, testProjectID)
		}
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL+"/api")
}

// writes is every request that changes something.
func (f *fakeEnvironmentsAPI) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var writes []string
	for _, request := range f.requests {
		if !strings.HasPrefix(request, http.MethodGet) {
			writes = append(writes, request)
		}
	}
	return writes
}

type exitCalled struct{}

// runEnvironments runs `infisical secrets-manager environments <args>` on a fresh command tree against
// the fake API, without a terminal, and returns stderr, stdout, and whether the command exited 1.
func runEnvironments(t *testing.T, fake *fakeEnvironmentsAPI, args ...string) (stderr, stdout string, exited bool) {
	t.Helper()
	fake.serve(t)
	t.Setenv(util.INFISICAL_TOKEN_NAME, "identity-access-token")
	t.Setenv(util.INFISICAL_PROJECT_ID_NAME, "")
	t.Chdir(t.TempDir())
	fakeTerminal(t, false, "", errors.New("must not prompt"))
	errOut := captureStderr(t)
	var out bytes.Buffer
	oldStdout, oldExit, oldTelemetry := util.GetStdoutWriter, exitProcess, Telemetry
	util.GetStdoutWriter = func() io.Writer { return &out }
	exitProcess = func(int) { panic(exitCalled{}) }
	Telemetry = telemetry.NewTelemetry(false)
	t.Cleanup(func() { util.GetStdoutWriter, exitProcess, Telemetry = oldStdout, oldExit, oldTelemetry })

	root := &cobra.Command{Use: "infisical"}
	product := &cobra.Command{Use: secretsManagerCommandName}
	product.AddCommand(buildEnvironmentsCmd())
	root.AddCommand(product)
	cmd, rest, err := root.Find(append([]string{secretsManagerCommandName, "environments"}, args...))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.ParseFlags(rest); err != nil {
		t.Fatal(err)
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
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
	return errOut.String(), out.String(), exited
}

func TestEnvironmentsGetListsAndShowsOne(t *testing.T) {
	fake := &fakeEnvironmentsAPI{}
	_, stdout, exited := runEnvironments(t, fake, "get", "--projectId", testProjectID, "-o", "json")
	var listed []map[string]string
	if exited || json.Unmarshal([]byte(stdout), &listed) != nil || len(listed) != 2 || listed[1]["slug"] != "staging" {
		t.Errorf("list: exited=%v stdout=%s", exited, stdout)
	}

	_, stdout, exited = runEnvironments(t, fake, "get", "staging", "--projectId", testProjectID, "-o", "json")
	if exited || !strings.Contains(stdout, `"position":2`) {
		t.Errorf("one: exited=%v stdout=%s", exited, stdout)
	}
}

func TestEnvironmentsErrors(t *testing.T) {
	cases := []struct {
		name string
		fake *fakeEnvironmentsAPI
		args []string
		code string
		next string
	}{
		{"missing slug", &fakeEnvironmentsAPI{}, []string{"get", "nope", "--projectId", testProjectID},
			errCodeEnvironmentNotFound, "environments get --projectId " + testProjectID},
		{"pending slug", &fakeEnvironmentsAPI{}, []string{"get", "qa", "--projectId", testProjectID},
			errCodeEnvironmentPending, "environments delete qa --force --projectId " + testProjectID},
		{"project 404", &fakeEnvironmentsAPI{missing: true}, []string{"get", "--projectId", testProjectID},
			errCodeProjectNotFound, "projects list"},
		{"another product", &fakeEnvironmentsAPI{projectType: "cert-manager"}, []string{"get", "--projectId", testProjectID},
			errCodeProjectTypeNotSupported, "projects list"},
		{"no project", &fakeEnvironmentsAPI{}, []string{"get"}, errCodeProjectNotLinked, "infisical init"},
		{"create taken", &fakeEnvironmentsAPI{}, []string{"create", "staging", "--projectId", testProjectID},
			errCodeEnvironmentExists, "environments get staging --projectId " + testProjectID},
		{"create pending", &fakeEnvironmentsAPI{}, []string{"create", "qa", "--projectId", testProjectID},
			errCodeEnvironmentPending, "delete qa --force"},
		{"update nothing", &fakeEnvironmentsAPI{}, []string{"update", "staging", "--projectId", testProjectID}, errCodeNothingToUpdate, ""},
		{"update to taken slug", &fakeEnvironmentsAPI{}, []string{"update", "staging", "--slug", "dev", "--projectId", testProjectID},
			errCodeEnvironmentExists, "environments get dev"},
		{"update missing", &fakeEnvironmentsAPI{}, []string{"update", "nope", "--name", "x", "--projectId", testProjectID}, errCodeEnvironmentNotFound, ""},
		{"delete pending without --force", &fakeEnvironmentsAPI{}, []string{"delete", "qa", "--yes", "--projectId", testProjectID},
			errCodeEnvironmentPending, "delete qa --force"},
		{"delete without a terminal", &fakeEnvironmentsAPI{}, []string{"delete", "staging", "--projectId", testProjectID},
			errCodeConfirmationRequired, "environments delete staging --output json --projectId " + testProjectID + " --yes"},
	}
	for _, c := range cases {
		stderr, _, exited := runEnvironments(t, c.fake, append(c.args, "-o", "json")...)
		var body struct {
			Error struct {
				Code string   `json:"code"`
				Next []string `json:"next"`
			} `json:"error"`
		}
		if !exited || json.Unmarshal([]byte(stderr), &body) != nil || body.Error.Code != c.code {
			t.Errorf("%s: want %s, got exited=%v stderr=%s", c.name, c.code, exited, stderr)
			continue
		}
		if c.next != "" && (len(body.Error.Next) == 0 || !strings.Contains(body.Error.Next[0], c.next)) {
			t.Errorf("%s: next %v should contain %q", c.name, body.Error.Next, c.next)
		}
		if writes := c.fake.writes(); len(writes) != 0 {
			t.Errorf("%s: nothing should be written, sent %v", c.name, writes)
		}
	}
}

// A delete never falls back to INFISICAL_PROJECT_ID or .infisical.yaml (CLI.md), and asks nothing of
// the API before saying so.
func TestEnvironmentsDeleteRequiresProjectID(t *testing.T) {
	fake := &fakeEnvironmentsAPI{}
	stderr, _, exited := runEnvironments(t, fake, "delete", "staging", "--yes")
	if !exited || !strings.Contains(stderr, "needs --projectId") || len(fake.requests) != 0 {
		t.Errorf("exited=%v requests=%v stderr=%s", exited, fake.requests, stderr)
	}
}

func TestEnvironmentsDeleteSendsWhatWasAskedFor(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"delete", "staging", "--yes"}, "DELETE /v1/projects/" + testProjectID + "/environments/" + testEnvironmentID},
		{[]string{"delete", "staging", "--force", "-y"}, "DELETE /v1/projects/" + testProjectID + "/environments/" + testEnvironmentID + "?hardDelete=true"},
		{[]string{"delete", "qa", "--force", "--yes"}, "DELETE /v1/projects/" + testProjectID + "/environments/" + testPendingID + "?hardDelete=true"},
	}
	for _, c := range cases {
		fake := &fakeEnvironmentsAPI{}
		stderr, _, exited := runEnvironments(t, fake, append(c.args, "--projectId", testProjectID)...)
		if writes := fake.writes(); exited || len(writes) != 1 || writes[0] != c.want {
			t.Errorf("%v: exited=%v writes=%v stderr=%s, want %s", c.args, exited, writes, stderr, c.want)
		}
	}
}

func TestEnvironmentsCreateAndUpdateSendOnlyWhatWasPassed(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"create", "preview"}, `POST /v1/projects/` + testProjectID + `/environments {"name":"preview","slug":"preview"}`},
		{[]string{"create", "preview", "--name", "Preview"}, `POST /v1/projects/` + testProjectID + `/environments {"name":"Preview","slug":"preview"}`},
		{[]string{"create", "preview", "--name", "  Preview  "}, `POST /v1/projects/` + testProjectID + `/environments {"name":"Preview","slug":"preview"}`},
		{[]string{"create", "preview", "--name", "   "}, `POST /v1/projects/` + testProjectID + `/environments {"name":"preview","slug":"preview"}`},
		{[]string{"update", "staging", "--name", " Stage "}, `PATCH /v1/projects/` + testProjectID + `/environments/` + testEnvironmentID + ` {"name":"Stage"}`},
		{[]string{"update", "staging", "--name", "Stage"}, `PATCH /v1/projects/` + testProjectID + `/environments/` + testEnvironmentID + ` {"name":"Stage"}`},
		{[]string{"update", "staging", "--slug", "stage", "--name", "Stage"}, `PATCH /v1/projects/` + testProjectID + `/environments/` + testEnvironmentID + ` {"name":"Stage","slug":"stage"}`},
		{[]string{"update", "staging", "--slug", "staging"}, `PATCH /v1/projects/` + testProjectID + `/environments/` + testEnvironmentID + ` {"slug":"staging"}`},
	}
	for _, c := range cases {
		fake := &fakeEnvironmentsAPI{}
		stderr, _, exited := runEnvironments(t, fake, append(c.args, "--projectId", testProjectID, "-o", "json")...)
		if writes := fake.writes(); exited || len(writes) != 1 || writes[0] != c.want {
			t.Errorf("%v: exited=%v writes=%v stderr=%s\nwant %s", c.args, exited, writes, stderr, c.want)
		}
	}
}

// An explicit empty --name or --slug is rejected before anything is sent, instead of PATCHing a
// blank value.
func TestEnvironmentUpdateRejectsEmptyValues(t *testing.T) {
	cases := map[string]string{
		`--name=`:      "--name can't be empty",
		`--name=   `:   "--name can't be empty",
		`--slug=`:      "--slug can't be empty",
		`--name=Stage`: "",
	}
	for flag, want := range cases {
		update, _, err := buildEnvironmentsCmd().Find([]string{"update"})
		if err != nil {
			t.Fatal(err)
		}
		if err := update.ParseFlags([]string{flag}); err != nil {
			t.Fatal(err)
		}
		_, err = environmentUpdate(update)
		if got := fmt.Sprint(err); (want == "" && err != nil) || (want != "" && got != want) {
			t.Errorf("%s: got %v, want %q", flag, err, want)
		}
	}
}

// Service tokens can't use these routes: one from the environment is ignored, like the projects
// commands do, so the command falls back to the login session.
func TestEnvironmentsRejectServiceTokens(t *testing.T) {
	for _, name := range []string{"get", "create", "update", "delete"} {
		cmd := findCommand(t, smPath([]string{"environments", name}))
		if !rejectsServiceTokens(cmd) {
			t.Errorf("environments %s should be marked serviceTokenUnsupported", name)
		}
	}
}

func TestEnvironmentsAreRegisteredOnlyUnderSecretsManager(t *testing.T) {
	for _, prefix := range []string{secretsManagerCommandName, secretsManagerAlias} {
		if cmd, _, err := RootCmd.Find([]string{prefix, "environments", "get"}); err != nil || cmd.Name() != "get" {
			t.Errorf("%s environments get should resolve: %v", prefix, err)
		}
	}
	if cmd, _, _ := RootCmd.Find([]string{"environments"}); cmd != RootCmd {
		t.Error("environments must not be added at the top level")
	}
}
