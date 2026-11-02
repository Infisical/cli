package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeProjectsAPI answers GET /v1/projects/slug/:slug, GET /v1/projects/:id, DELETE /v1/projects/:id
// and POST /v1/projects like the backend, and records every request. With notMember, the project
// routes answer the way the backend does for a user who isn't a member of the project.
type fakeProjectsAPI struct {
	projectType string
	protected   bool
	notMember   bool
	denyCreate  bool
	mu          sync.Mutex
	requests    []string
}

func (f *fakeProjectsAPI) serve(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		line := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/api")
		if r.URL.RawQuery != "" {
			line += "?" + r.URL.RawQuery
		}
		f.mu.Lock()
		f.requests = append(f.requests, line)
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
		case f.notMember && strings.HasPrefix(r.URL.Path, "/api/v1/projects/"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"ProjectMembershipNotFound","message":"You are not a member of this project with ID ` + testProjectID + `.","reqId":"req-test"}`))
		case f.denyCreate && r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"PermissionDenied","message":"You are not allowed to create on workspace","reqId":"req-test"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects":
			_ = json.NewEncoder(w).Encode(map[string]any{"project": project})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/slug/payments-api":
			_ = json.NewEncoder(w).Encode(project)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/"+testProjectID:
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
