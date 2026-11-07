package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

// fakeProjectsAPI answers GET /v1/projects/slug/:slug, GET /v1/projects/:id, PATCH /v1/projects/:id,
// DELETE /v1/projects/:id and POST /v1/projects like the backend, and records every request, with the
// body of each PATCH in patches. With notMember, the project
// routes answer the way the backend does for a user who isn't a member of the project.
type fakeProjectsAPI struct {
	projectType string
	protected   bool
	notMember   bool
	denyCreate  bool
	expired     bool
	mu          sync.Mutex
	requests    []string
	patches     []string
}

func (f *fakeProjectsAPI) serve(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		line := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/api")
		if r.URL.RawQuery != "" {
			line += "?" + r.URL.RawQuery
		}
		f.mu.Lock()
		f.requests = append(f.requests, line)
		if r.Method == http.MethodPatch {
			f.patches = append(f.patches, string(body))
		}
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		projectType := f.projectType
		if projectType == "" {
			projectType = secretManagerProjectType
		}
		project := map[string]any{"id": testProjectID, "name": "Payments API", "slug": "payments-api", "type": projectType,
			"orgId": "org-1", "hasDeleteProtection": f.protected,
			"environments": []map[string]string{{"id": "e1", "name": "Development", "slug": "dev"}}}
		switch {
		case f.expired:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"UnauthorizedError","message":"Token expired","reqId":"req-test"}`))
		case f.notMember && strings.HasPrefix(r.URL.Path, "/api/v1/projects/"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"ProjectMembershipNotFound","message":"You are not a member of this project with ID ` + testProjectID + `.","reqId":"req-test"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects":
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": []any{project}})
		case f.denyCreate && r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"PermissionDenied","message":"You are not allowed to create on workspace","reqId":"req-test"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects":
			_ = json.NewEncoder(w).Encode(map[string]any{"project": project})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/slug/payments-api":
			_ = json.NewEncoder(w).Encode(project)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/"+testProjectID:
			_ = json.NewEncoder(w).Encode(map[string]any{"project": project})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/projects/"+testProjectID:
			delete(project, "environments")
			var update map[string]string
			_ = json.Unmarshal(body, &update)
			for field, value := range update {
				project[field] = value
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"project": project})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/projects/"+testProjectID:
			delete(project, "environments")
			_ = json.NewEncoder(w).Encode(map[string]any{"project": project})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"NotFound","message":"not found","reqId":"req-test"}`))
		}
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL+"/api")
}

func (f *fakeProjectsAPI) deletes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var deletes []string
	for _, request := range f.requests {
		if strings.HasPrefix(request, http.MethodDelete) {
			deletes = append(deletes, request)
		}
	}
	return deletes
}

func runProjects(t *testing.T, fake *fakeProjectsAPI, args ...string) (stderr, stdout string, exited bool) {
	t.Helper()
	fake.serve(t)
	return runUnderSecretsManager(t, buildProjectsCmd, append([]string{"projects"}, args...)...)
}

func errorCode(t *testing.T, stderr string) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(stderr), &body)
	return body.Error.Code
}

// `projects get <slug>` prints the same shape as `projects get --projectId`, so it doesn't leak the
// settings the delete reads.
func TestProjectsGetBySlug(t *testing.T) {
	fake := &fakeProjectsAPI{}
	_, stdout, exited := runProjects(t, fake, "get", "payments-api", "-o", "json")
	var project map[string]any
	if exited || json.Unmarshal([]byte(stdout), &project) != nil || project["id"] != testProjectID || project["slug"] != "payments-api" {
		t.Fatalf("exited=%v stdout=%s", exited, stdout)
	}
	if _, leaked := project["hasDeleteProtection"]; leaked {
		t.Errorf("projects get -o json changed shape: %s", stdout)
	}
	if len(project["environments"].([]any)) != 1 {
		t.Errorf("environments missing: %s", stdout)
	}
}

func TestProjectsGetBySlugErrors(t *testing.T) {
	fake := &fakeProjectsAPI{}
	stderr, _, exited := runProjects(t, fake, "get", "payments-api", "--projectId", testProjectID, "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeInvalidFlagValue || len(fake.requests) != 0 {
		t.Errorf("slug and --projectId: exited=%v requests=%v stderr=%s", exited, fake.requests, stderr)
	}

	stderr, _, exited = runProjects(t, &fakeProjectsAPI{}, "get", "nope", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeProjectNotFound || !strings.Contains(stderr, `Project \"nope\"`) {
		t.Errorf("missing slug: exited=%v stderr=%s", exited, stderr)
	}

	stderr, _, exited = runProjects(t, &fakeProjectsAPI{projectType: "cert-manager"}, "get", "payments-api", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeProjectTypeNotSupported {
		t.Errorf("another product: exited=%v stderr=%s", exited, stderr)
	}

	stderr, _, exited = runProjects(t, &fakeProjectsAPI{projectType: "cert-manager"}, "get", "--projectId", testProjectID, "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeProjectTypeNotSupported {
		t.Errorf("another product by --projectId: exited=%v stderr=%s", exited, stderr)
	}
}

// Someone who isn't a member gets project_not_found naming what they typed, never the project's ID.
func TestProjectsNotAMember(t *testing.T) {
	for _, args := range [][]string{{"get", "payments-api"}, {"delete", "payments-api", "--yes"}} {
		fake := &fakeProjectsAPI{notMember: true}
		stderr, _, exited := runProjects(t, fake, append(args, "-o", "json")...)
		if !exited || errorCode(t, stderr) != errCodeProjectNotFound || !strings.Contains(stderr, `Project \"payments-api\"`) ||
			strings.Contains(stderr, testProjectID) || len(fake.deletes()) != 0 {
			t.Errorf("%v: exited=%v deletes=%v stderr=%s", args, exited, fake.deletes(), stderr)
		}
	}
}

// The --projectId path reports the same codes as the slug path.
func TestProjectsGetByIDErrors(t *testing.T) {
	stderr, _, exited := runProjects(t, &fakeProjectsAPI{}, "get", "--projectId", "00000000-0000-4000-8000-000000000000", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeProjectNotFound {
		t.Errorf("unknown ID: exited=%v stderr=%s", exited, stderr)
	}
	stderr, _, exited = runProjects(t, &fakeProjectsAPI{notMember: true}, "get", "--projectId", testProjectID, "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeProjectNotFound {
		t.Errorf("not a member: exited=%v stderr=%s", exited, stderr)
	}
	fake := &fakeProjectsAPI{}
	stderr, _, exited = runProjects(t, fake, "get", "--projectId", " ", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeInvalidFlagValue || len(fake.requests) != 0 {
		t.Errorf("empty --projectId: exited=%v requests=%v stderr=%s", exited, fake.requests, stderr)
	}
}

// get with no slug and no --projectId lists, like get for every resource, even with INFISICAL_PROJECT_ID
// set and in a directory that .infisical.yaml links to a project. projects list does the same, hidden.
func TestProjectsGetWithoutASlugLists(t *testing.T) {
	linkedProject := func() {
		t.Setenv(util.INFISICAL_PROJECT_ID_NAME, testProjectID)
		if err := os.WriteFile(util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME, []byte("secrets-management:\n  project-id: "+testProjectID+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"get"}, {"list"}} {
		fake := &fakeProjectsAPI{}
		fake.serve(t)
		_, stdout, exited := runUnderSecretsManagerAfter(t, linkedProject, buildProjectsCmd, append([]string{"projects"}, append(args, "-o", "json")...)...)
		var projects []map[string]any
		if exited || json.Unmarshal([]byte(stdout), &projects) != nil || len(projects) != 1 || projects[0]["slug"] != "payments-api" {
			t.Errorf("%v: exited=%v stdout=%s", args, exited, stdout)
		}
		if len(fake.requests) != 1 || fake.requests[0] != "GET /v1/projects?type=secret-manager" {
			t.Errorf("%v: requests=%v", args, fake.requests)
		}
	}
	list, _, _ := buildProjectsCmd().Find([]string{"list"})
	if !list.Hidden {
		t.Error("projects list should be hidden: get lists")
	}
}

func TestProjectsListErrors(t *testing.T) {
	stderr, stdout, exited := runProjects(t, &fakeProjectsAPI{expired: true}, "list", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeAuthRequired || stdout != "" {
		t.Errorf("exited=%v stdout=%q stderr=%s", exited, stdout, stderr)
	}
}

// The argument can be the project's ID instead of its slug, which is how a service token names one.
func TestProjectsGetByIDArgument(t *testing.T) {
	fake := &fakeProjectsAPI{}
	_, stdout, exited := runProjects(t, fake, "get", testProjectID, "-o", "json")
	var project map[string]any
	if exited || json.Unmarshal([]byte(stdout), &project) != nil || project["id"] != testProjectID ||
		len(fake.requests) != 1 || fake.requests[0] != "GET /v1/projects/"+testProjectID {
		t.Errorf("exited=%v requests=%v stdout=%s", exited, fake.requests, stdout)
	}

	fake = &fakeProjectsAPI{}
	stderr, _, exited := runProjects(t, fake, "get", testProjectID, "--projectId", testProjectID, "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeInvalidFlagValue || len(fake.requests) != 0 {
		t.Errorf("ID argument and --projectId: exited=%v requests=%v stderr=%s", exited, fake.requests, stderr)
	}

	get, _, _ := buildProjectsCmd().Find([]string{"get"})
	if flag := get.Flags().Lookup("projectId"); flag == nil || !flag.Hidden || flag.Deprecated == "" || !strings.Contains(flag.Deprecated, "<slug-or-id>") {
		t.Errorf("--projectId should keep working, hidden and deprecated in favor of the argument: %+v", flag)
	}
}

// The --projectId deprecation notice goes to stderr in text, but never with -o json or yaml, whose
// stderr must stay one document, nor with --silent.
func TestProjectsGetDeprecationNoticeRespectsOutput(t *testing.T) {
	for _, c := range []struct {
		args   []string
		notice bool
	}{
		{[]string{"--projectId", testProjectID}, true},
		{[]string{"--projectId", testProjectID, "-o", "json"}, false},
		{[]string{"-o", "yaml", "--projectId", testProjectID}, false},
		{[]string{"--projectId", testProjectID, "--silent"}, false},
	} {
		root := &cobra.Command{Use: "infisical"}
		root.PersistentFlags().Bool("silent", false, "")
		root.AddCommand(buildProjectsCmd())
		get, rest, err := root.Find(append([]string{"projects", "get"}, c.args...))
		if err != nil || get.ParseFlags(rest) != nil {
			t.Fatal(err)
		}
		stderr := captureStderr(t)
		get.PreRun(get, get.Flags().Args())
		if got := strings.Contains(stderr.String(), "Flag --projectId has been deprecated"); got != c.notice {
			t.Errorf("%v: notice=%v, want %v (stderr=%q)", c.args, got, c.notice, stderr.String())
		}
	}
}

func TestProjectsGetBySlugRejectsServiceTokens(t *testing.T) {
	fake := &fakeProjectsAPI{}
	stderr, _, exited := runProjects(t, fake, "get", "payments-api", "--token", "st.fake.service.token", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeServiceTokenUnsupported || len(fake.requests) != 0 || strings.Contains(stderr, "st.fake") {
		t.Errorf("exited=%v requests=%v stderr=%s", exited, fake.requests, stderr)
	}
}

func TestProjectsCreate(t *testing.T) {
	stderr, stdout, exited := runProjects(t, &fakeProjectsAPI{}, "create", "--name", "Payments API")
	if exited || !strings.Contains(stderr, "Created project Payments API") || strings.Contains(stdout, "Created project") {
		t.Errorf("the success notice belongs on stderr: exited=%v stdout=%q stderr=%q", exited, stdout, stderr)
	}

	fake := &fakeProjectsAPI{}
	stderr, _, exited = runProjects(t, fake, "create", "--name", "  ", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeInvalidFlagValue || len(fake.requests) != 0 {
		t.Errorf("blank --name: exited=%v requests=%v stderr=%s", exited, fake.requests, stderr)
	}

	stderr, _, exited = runProjects(t, &fakeProjectsAPI{denyCreate: true}, "create", "--name", "Payments API", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodePermissionDenied {
		t.Errorf("denied: exited=%v stderr=%s", exited, stderr)
	}
}

// A delete is refused before anything is sent when the project can't or mustn't be deleted.
func TestProjectsDeleteRefusesBeforeDeleting(t *testing.T) {
	cases := []struct {
		name string
		fake *fakeProjectsAPI
		args []string
		code string
	}{
		{"delete protection", &fakeProjectsAPI{protected: true}, []string{"payments-api", "--yes"}, errCodeProjectDeleteProtected},
		{"another product", &fakeProjectsAPI{projectType: "kms"}, []string{"payments-api", "--yes"}, errCodeProjectTypeNotSupported},
		{"missing slug", &fakeProjectsAPI{}, []string{"nope", "--yes"}, errCodeProjectNotFound},
		{"no terminal, no --yes", &fakeProjectsAPI{}, []string{"payments-api"}, errCodeConfirmationRequired},
	}
	for _, c := range cases {
		stderr, _, exited := runProjects(t, c.fake, append([]string{"delete"}, append(c.args, "-o", "json")...)...)
		if !exited || errorCode(t, stderr) != c.code || len(c.fake.deletes()) != 0 {
			t.Errorf("%s: want %s, got exited=%v deletes=%v stderr=%s", c.name, c.code, exited, c.fake.deletes(), stderr)
		}
	}

	stderr, _, _ := runProjects(t, &fakeProjectsAPI{}, "delete", "payments-api")
	if !strings.Contains(stderr, "run: infisical secrets-manager projects delete payments-api --yes") {
		t.Errorf("the rerun should carry --yes: %s", stderr)
	}
}

func TestProjectsDeleteSendsWhatWasAskedFor(t *testing.T) {
	fake := &fakeProjectsAPI{}
	stderr, stdout, exited := runProjects(t, fake, "delete", "payments-api", "--yes")
	if exited || len(fake.deletes()) != 1 || fake.deletes()[0] != "DELETE /v1/projects/"+testProjectID || stdout != "" ||
		!strings.Contains(stderr, "Permanently deleted project Payments API.") {
		t.Errorf("delete: exited=%v deletes=%v stdout=%q stderr=%q", exited, fake.deletes(), stdout, stderr)
	}

	_, stdout, _ = runProjects(t, &fakeProjectsAPI{}, "delete", "payments-api", "--yes", "-o", "json")
	var deleted map[string]any
	if json.Unmarshal([]byte(stdout), &deleted) != nil || deleted["id"] != testProjectID {
		t.Errorf("-o json: %s", stdout)
	}
}

func TestProjectsDeleteRejectsServiceTokens(t *testing.T) {
	if !rejectsServiceTokens(findCommand(t, smPath([]string{"projects", "delete"}))) {
		t.Error("projects delete should be marked serviceTokenUnsupported")
	}
}

// The root's "session is being overwritten" warning and the request must agree on when a service
// token from INFISICAL_TOKEN is set aside: for listing and for a slug, whose routes reject it, but not
// for a lookup by --projectId, and never for one passed with --token, which is refused instead.
func TestProjectsGetIgnoresAnEnvServiceTokenUnlessByID(t *testing.T) {
	envToken := &models.TokenDetails{Type: util.SERVICE_TOKEN_IDENTIFIER, Token: "st.a.b.c", Source: "INFISICAL_TOKEN environment variable"}
	cases := []struct {
		name    string
		flags   []string
		args    []string
		ignored bool
	}{
		{"slug", nil, []string{"payments-api"}, true},
		{"listing", nil, nil, true},
		{"by ID", nil, []string{testProjectID}, false},
		{"by --projectId", []string{"--projectId", testProjectID}, nil, false},
		{"--token", []string{"--token", "st.a.b.c"}, []string{"payments-api"}, false},
	}
	for _, c := range cases {
		get, _, err := buildProjectsCmd().Find([]string{"get"})
		if err != nil || get.ParseFlags(c.flags) != nil {
			t.Fatal(err)
		}
		if got := ignoresEnvServiceToken(get, c.args, envToken); got != c.ignored {
			t.Errorf("%s: ignored=%v, want %v", c.name, got, c.ignored)
		}
	}
}

func TestProjectsUpdateSendsOnlyWhatChanged(t *testing.T) {
	cases := []struct {
		args []string
		sent string
	}{
		{[]string{"payments-api", "--name", " Payments "}, `{"name":"Payments"}`},
		{[]string{testProjectID, "--slug", "payments"}, `{"slug":"payments"}`},
		{[]string{"payments-api", "--description", ""}, `{"description":""}`},
		{[]string{"payments-api", "--name", "P", "--slug", "p-api", "--description", "Billing"}, `{"name":"P","description":"Billing","slug":"p-api"}`},
	}
	for _, c := range cases {
		fake := &fakeProjectsAPI{}
		_, stdout, exited := runProjects(t, fake, append([]string{"update"}, append(c.args, "-o", "json")...)...)
		var updated map[string]any
		if exited || len(fake.patches) != 1 || fake.patches[0] != c.sent || json.Unmarshal([]byte(stdout), &updated) != nil || updated["id"] != testProjectID {
			t.Errorf("%v: exited=%v patches=%v stdout=%s", c.args, exited, fake.patches, stdout)
		}
	}

	stderr, stdout, _ := runProjects(t, &fakeProjectsAPI{}, "update", "payments-api", "--name", "Billing")
	if !strings.Contains(stderr, "Updated project Billing") || strings.Contains(stdout, "Updated project") {
		t.Errorf("text: stderr=%q stdout=%q", stderr, stdout)
	}
}

// Every refusal happens before the PATCH. The flag checks happen before any request at all.
func TestProjectsUpdateRefusesBeforeUpdating(t *testing.T) {
	cases := []struct {
		name     string
		fake     *fakeProjectsAPI
		args     []string
		code     string
		requests bool
	}{
		{"no change flags", &fakeProjectsAPI{}, []string{"payments-api"}, errCodeNothingToUpdate, false},
		{"empty name", &fakeProjectsAPI{}, []string{"payments-api", "--name", " "}, errCodeInvalidFlagValue, false},
		{"empty slug", &fakeProjectsAPI{}, []string{"payments-api", "--slug", ""}, errCodeInvalidFlagValue, false},
		{"missing slug", &fakeProjectsAPI{}, []string{"nope", "--name", "x"}, errCodeProjectNotFound, true},
		{"missing ID", &fakeProjectsAPI{}, []string{"00000000-0000-4000-8000-000000000000", "--name", "x"}, errCodeProjectNotFound, true},
		{"another product", &fakeProjectsAPI{projectType: "kms"}, []string{"payments-api", "--name", "x"}, errCodeProjectTypeNotSupported, true},
		{"not a member", &fakeProjectsAPI{notMember: true}, []string{testProjectID, "--name", "x"}, errCodeProjectNotFound, true},
	}
	for _, c := range cases {
		stderr, stdout, exited := runProjects(t, c.fake, append([]string{"update"}, append(c.args, "-o", "json")...)...)
		if !exited || errorCode(t, stderr) != c.code || stdout != "" || len(c.fake.patches) != 0 || (len(c.fake.requests) > 0) != c.requests {
			t.Errorf("%s: want %s, got exited=%v requests=%v stderr=%s", c.name, c.code, exited, c.fake.requests, stderr)
		}
	}
}

func TestProjectsUpdateRejectsServiceTokens(t *testing.T) {
	if !rejectsServiceTokens(findCommand(t, smPath([]string{"projects", "update"}))) {
		t.Error("projects update should be marked serviceTokenUnsupported")
	}
}
