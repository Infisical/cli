package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
)

const testFolderID = "5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a"

// fakeFoldersAPI answers the routes the folders commands call. Every project ID is a Secrets
// Management project with dev and staging. The folders at /backend in dev are api and jobs; old.name,
// which predates the backend's naming rule; and gone, which disappears before an update or delete lands.
type fakeFoldersAPI struct {
	projectType string
	mu          sync.Mutex
	requests    []string
}

func (f *fakeFoldersAPI) serve(t *testing.T) {
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
		route := strings.TrimPrefix(r.URL.Path, "/api")
		switch {
		case route == "/v2/service-token":
			_, _ = fmt.Fprintf(w, `{"_id":"st","workspace":%q,"scopes":[{"environment":"dev","secretPath":"/"}]}`, tokenProjectID)
		case r.Method == http.MethodGet && strings.HasPrefix(route, "/v1/projects/"):
			projectType := f.projectType
			if projectType == "" {
				projectType = secretManagerProjectType
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"project": map[string]any{
				"id": strings.TrimPrefix(route, "/v1/projects/"), "name": "payments-api", "slug": "payments-api", "type": projectType,
				"environments":        []map[string]string{{"id": "e1", "name": "Development", "slug": "dev"}, {"id": "e2", "name": "Staging", "slug": "staging"}},
				"deletedEnvironments": []map[string]string{{"id": "e3", "name": "QA", "slug": "qa", "deleteAfter": "2026-11-12T10:00:00.000Z"}},
			}})
		case r.Method == http.MethodGet && route == "/v2/folders":
			if r.URL.Query().Get("environment") == "dev" && r.URL.Query().Get("path") == "/backend" {
				_, _ = fmt.Fprintf(w, `{"folders":[{"id":%q,"name":"api","description":"Public API"},{"id":"f2","name":"jobs"},{"id":"f3","name":"old.name"},{"id":"f4","name":"gone"}]}`, testFolderID)
				return
			}
			_, _ = w.Write([]byte(`{"folders":[]}`))
		case r.Method == http.MethodPost && route == "/v2/folders":
			var request map[string]any
			_ = json.Unmarshal(body, &request)
			_, _ = fmt.Fprintf(w, `{"folder":{"id":"new","name":%q,"path":"/x"}}`, request["name"])
		case (r.Method == http.MethodPatch || r.Method == http.MethodDelete) && strings.HasSuffix(route, "/f4"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"NotFound","message":"Folder with ID 'f4' not found","reqId":"req-gone"}`))
		case r.Method == http.MethodPatch || r.Method == http.MethodDelete:
			var request map[string]any
			_ = json.Unmarshal(body, &request)
			name, _ := request["name"].(string)
			if name == "" {
				name = "api"
			}
			_, _ = fmt.Fprintf(w, `{"folder":{"id":%q,"name":%q}}`, testFolderID, name)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"NotFound","message":"not found"}`))
		}
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL+"/api")
}

func (f *fakeFoldersAPI) sent(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var matched []string
	for _, request := range f.requests {
		if strings.HasPrefix(request, prefix) {
			matched = append(matched, request)
		}
	}
	return matched
}

func (f *fakeFoldersAPI) writes() []string {
	var writes []string
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
		writes = append(writes, f.sent(method+" /v2/folders")...)
	}
	return writes
}

func runFolders(t *testing.T, fake *fakeFoldersAPI, args ...string) (stderr, stdout string, exited bool) {
	t.Helper()
	fake.serve(t)
	return runUnderSecretsManager(t, buildFoldersCmd, append([]string{"folders"}, args...)...)
}

// body is the JSON body of the only request sent with this method and path prefix.
func (f *fakeFoldersAPI) body(t *testing.T, prefix string) map[string]any {
	t.Helper()
	sent := f.sent(prefix)
	if len(sent) != 1 {
		t.Fatalf("want one %s, got %v", prefix, sent)
	}
	_, raw, _ := strings.Cut(sent[0], " {")
	var body map[string]any
	if err := json.Unmarshal([]byte("{"+raw), &body); err != nil {
		t.Fatalf("%s: %v", sent[0], err)
	}
	return body
}

func TestFoldersGetListsAndShowsOne(t *testing.T) {
	fake := &fakeFoldersAPI{}
	_, stdout, exited := runFolders(t, fake, "get", "--path", "backend/", "--projectId", testProjectID, "-o", "json")
	var listed []folderOutput
	if exited || json.Unmarshal([]byte(stdout), &listed) != nil || len(listed) != 4 || listed[0].Path != "/backend/api" || listed[0].Environment != "dev" || listed[0].Description != "Public API" {
		t.Errorf("list: exited=%v stdout=%s", exited, stdout)
	}
	if got := fake.sent("GET /v2/folders"); len(got) != 1 || !strings.Contains(got[0], "path=%2Fbackend") {
		t.Errorf("the path is sent normalized: %v", got)
	}

	_, stdout, exited = runFolders(t, &fakeFoldersAPI{}, "get", "--env", "staging", "--projectId", testProjectID, "-o", "json")
	if exited || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("an empty list is [], not null: exited=%v stdout=%s", exited, stdout)
	}

	_, stdout, exited = runFolders(t, &fakeFoldersAPI{}, "get", "api", "--path", "/backend", "--projectId", testProjectID, "-o", "json")
	var one folderOutput
	if exited || json.Unmarshal([]byte(stdout), &one) != nil || one.ID != testFolderID || one.Path != "/backend/api" {
		t.Errorf("one: exited=%v stdout=%s", exited, stdout)
	}
}

func TestFoldersRefuseBeforeWriting(t *testing.T) {
	scope := []string{"--path", "/backend", "--projectId", testProjectID, "-o", "json"}
	cases := []struct {
		name      string
		args      []string
		code      string
		noRequest bool
	}{
		{"missing folder", append([]string{"get", "nope"}, scope...), errCodeFolderNotFound, false},
		{"a nested path as the name", append([]string{"get", "backend/api"}, scope...), errCodeFolderNotFound, false},
		{"name with a space", append([]string{"create", "my folder"}, scope...), errCodeInvalidArgument, true},
		{"create an existing folder", append([]string{"create", "api"}, scope...), errCodeFolderExists, false},
		{"update without change flags", append([]string{"update", "api"}, scope...), errCodeNothingToUpdate, true},
		{"update to an empty name", append([]string{"update", "api", "--name", " "}, scope...), errCodeInvalidFlagValue, true},
		{"update to an invalid name", append([]string{"update", "api", "--name", "a/b"}, scope...), errCodeInvalidFlagValue, true},
		{"rename onto a sibling", append([]string{"update", "api", "--name", "jobs"}, scope...), errCodeFolderExists, false},
		{"update a missing folder", append([]string{"update", "nope", "--name", "x"}, scope...), errCodeFolderNotFound, false},
		{"unknown environment", append([]string{"get", "--env", "prod"}, scope...), errCodeEnvironmentNotFound, false},
		{"environment pending deletion", append([]string{"create", "x", "--env", "qa"}, scope...), errCodeEnvironmentPending, false},
		{"delete without --projectId", []string{"delete", "api", "--path", "/backend", "--yes", "-o", "json"}, errCodeProjectRequired, true},
		{"delete a missing folder", append([]string{"delete", "nope", "--yes"}, scope...), errCodeFolderNotFound, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeFoldersAPI{}
			stderr, stdout, exited := runFolders(t, fake, c.args...)
			if !exited || errorCode(t, stderr) != c.code || stdout != "" {
				t.Errorf("exited=%v stdout=%q stderr=%s", exited, stdout, stderr)
			}
			if len(fake.writes()) != 0 {
				t.Errorf("wrote %v", fake.writes())
			}
			if c.noRequest && len(fake.requests) != 0 {
				t.Errorf("sent %v before refusing", fake.requests)
			}
		})
	}

	fake := &fakeFoldersAPI{projectType: "cert-manager"}
	stderr, _, exited := runFolders(t, fake, "get", "--projectId", testProjectID, "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeProjectTypeNotSupported || len(fake.sent("GET /v2/folders")) != 0 {
		t.Errorf("cert-manager project: exited=%v stderr=%s sent=%v", exited, stderr, fake.requests)
	}
}

func TestFoldersCreateSendsWhatWasGiven(t *testing.T) {
	fake := &fakeFoldersAPI{}
	stderr, stdout, exited := runFolders(t, fake, "create", "billing", "--path", "/backend/", "--projectId", testProjectID, "-o", "json")
	body := fake.body(t, "POST /v2/folders")
	if exited || body["name"] != "billing" || body["path"] != "/backend" || body["environment"] != "dev" || body["projectId"] != testProjectID {
		t.Errorf("exited=%v body=%v stderr=%s", exited, body, stderr)
	}
	if _, set := body["description"]; set {
		t.Errorf("description sent without --description: %v", body)
	}
	if !strings.Contains(stdout, `"path":"/backend/billing"`) {
		t.Errorf("stdout=%s", stdout)
	}

	fake = &fakeFoldersAPI{}
	_, _, _ = runFolders(t, fake, "create", "billing", "--description", "Invoices", "--projectId", testProjectID, "-o", "json")
	if body := fake.body(t, "POST /v2/folders"); body["description"] != "Invoices" || body["path"] != "/" {
		t.Errorf("body=%v", body)
	}
}

func TestFoldersUpdateSendsOnlyWhatChanged(t *testing.T) {
	scope := []string{"--path", "/backend", "--projectId", testProjectID, "-o", "json"}

	fake := &fakeFoldersAPI{}
	_, _, exited := runFolders(t, fake, append([]string{"update", "api", "--name", "public-api"}, scope...)...)
	body := fake.body(t, "PATCH /v2/folders/"+testFolderID)
	if _, set := body["description"]; exited || set || body["name"] != "public-api" || body["path"] != "/backend" {
		t.Errorf("rename: exited=%v body=%v", exited, body)
	}

	fake = &fakeFoldersAPI{}
	_, _, exited = runFolders(t, fake, append([]string{"update", "api", "--description", ""}, scope...)...)
	body = fake.body(t, "PATCH /v2/folders/"+testFolderID)
	if description, set := body["description"]; exited || !set || description != "" || body["name"] != "api" {
		t.Errorf("clearing the description keeps the name: exited=%v body=%v", exited, body)
	}
}

func TestFoldersDeleteAsksAndNeverFallsBack(t *testing.T) {
	scope := []string{"--path", "/backend", "--projectId", testProjectID}

	fake := &fakeFoldersAPI{}
	stderr, _, exited := runFolders(t, fake, append([]string{"delete", "api", "-o", "json"}, scope...)...)
	var failure struct {
		Error struct {
			Next []string `json:"next"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(stderr), &failure)
	want := "infisical secrets-manager folders delete api --output json --path /backend --projectId " + testProjectID + " --env dev --yes"
	if !exited || errorCode(t, stderr) != errCodeConfirmationRequired || len(failure.Error.Next) != 1 || failure.Error.Next[0] != want {
		t.Errorf("no terminal: exited=%v stderr=%s want next %q", exited, stderr, want)
	}
	if len(fake.writes()) != 0 {
		t.Errorf("deleted without confirmation: %v", fake.writes())
	}

	fake = &fakeFoldersAPI{}
	_, stdout, exited := runFolders(t, fake, append([]string{"delete", "api", "--yes", "-o", "json"}, scope...)...)
	body := fake.body(t, "DELETE /v2/folders/"+testFolderID)
	if exited || body["forceDelete"] != true || body["path"] != "/backend" || !strings.Contains(stdout, testFolderID) {
		t.Errorf("the delete removes the contents, as the prompt says: exited=%v body=%v stdout=%s", exited, body, stdout)
	}

	question := "This deletes folder /backend/api in the dev environment of project \"payments-api\", with every secret, dynamic secret and folder inside it."
	for answer, deletes := range map[string]bool{"api": true, "jobs": false} {
		fake = &fakeFoldersAPI{}
		fake.serve(t)
		var calls *int
		setup := func() { calls = fakeTerminal(t, true, answer, nil) }
		stderr, _, exited := runUnderSecretsManagerAfter(t, setup, buildFoldersCmd, append([]string{"folders", "delete", "api"}, scope...)...)
		if *calls != 1 || !strings.Contains(stderr, question) || exited == deletes || (len(fake.writes()) == 1) != deletes {
			t.Errorf("typing %q at a terminal: prompts=%d exited=%v writes=%v stderr=%s", answer, *calls, exited, fake.writes(), stderr)
		}
	}

	fake = &fakeFoldersAPI{}
	fake.serve(t)
	setup := func() { t.Setenv(util.INFISICAL_PROJECT_ID_NAME, testProjectID) }
	stderr, _, exited = runUnderSecretsManagerAfter(t, setup, buildFoldersCmd, "folders", "delete", "api", "--path", "/backend", "--yes", "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeProjectRequired || len(fake.requests) != 0 {
		t.Errorf("INFISICAL_PROJECT_ID must not pick the project of a delete: exited=%v stderr=%s sent=%v", exited, stderr, fake.requests)
	}
}

func TestFoldersWithAServiceToken(t *testing.T) {
	setup := func() { t.Setenv(util.INFISICAL_TOKEN_NAME, "st.id.secret.key") }

	fake := &fakeFoldersAPI{}
	fake.serve(t)
	stderr, _, exited := runUnderSecretsManagerAfter(t, setup, buildFoldersCmd, "folders", "create", "x", "--projectId", testProjectID, "-o", "json")
	if !exited || errorCode(t, stderr) != errCodeTokenProjectMismatch || len(fake.sent("GET /v2/folders")) != 0 || len(fake.writes()) != 0 {
		t.Errorf("another project: exited=%v stderr=%s sent=%v", exited, stderr, fake.requests)
	}

	fake = &fakeFoldersAPI{}
	fake.serve(t)
	_, _, exited = runUnderSecretsManagerAfter(t, setup, buildFoldersCmd, "folders", "create", "x", "-o", "json")
	if body := fake.body(t, "POST /v2/folders"); exited || body["projectId"] != tokenProjectID {
		t.Errorf("no project selected uses the token's: exited=%v body=%v", exited, body)
	}
}

func TestSecretsFoldersIsHiddenUnderSecretsManager(t *testing.T) {
	legacy := findCommand(t, []string{secretsManagerCommandName, "secrets", "folders"})
	if !legacy.Hidden || legacy.Name() != "folders" {
		t.Errorf("secrets-manager secrets folders: hidden=%v name=%s", legacy.Hidden, legacy.Name())
	}
	if top := findCommand(t, []string{"secrets", "folders"}); top.Hidden {
		t.Error("the top-level secrets folders must stay visible")
	}
	if replacement := findCommand(t, []string{secretsManagerCommandName, "folders", "update"}); replacement.Hidden {
		t.Error("secrets-manager folders update must be visible")
	}
}

// Only new names are checked against the backend's rule, so a folder named before the rule existed
// stays reachable.
func TestFoldersReachNamesThatPredateTheRule(t *testing.T) {
	scope := []string{"--path", "/backend", "--projectId", testProjectID, "-o", "json"}

	_, stdout, exited := runFolders(t, &fakeFoldersAPI{}, append([]string{"get", "old.name"}, scope...)...)
	if exited || !strings.Contains(stdout, `"id":"f3"`) {
		t.Errorf("get: exited=%v stdout=%s", exited, stdout)
	}
	fake := &fakeFoldersAPI{}
	_, _, exited = runFolders(t, fake, append([]string{"update", "old.name", "--name", "renamed"}, scope...)...)
	if body := fake.body(t, "PATCH /v2/folders/f3"); exited || body["name"] != "renamed" {
		t.Errorf("update: exited=%v body=%v", exited, body)
	}
	fake = &fakeFoldersAPI{}
	_, _, exited = runFolders(t, fake, append([]string{"delete", "old.name", "--yes"}, scope...)...)
	if exited || len(fake.sent("DELETE /v2/folders/f3")) != 1 {
		t.Errorf("delete: exited=%v sent=%v", exited, fake.requests)
	}
}

func TestFoldersKeepTheRequestOfAFolderThatDisappeared(t *testing.T) {
	scope := []string{"--path", "/backend", "--projectId", testProjectID, "-o", "json"}
	for _, args := range [][]string{{"update", "gone", "--name", "x"}, {"delete", "gone", "--yes"}} {
		stderr, _, exited := runFolders(t, &fakeFoldersAPI{}, append(args, scope...)...)
		var failure struct {
			Error struct {
				Code       string `json:"code"`
				StatusCode int    `json:"statusCode"`
				RequestID  string `json:"requestId"`
			} `json:"error"`
		}
		_ = json.Unmarshal([]byte(stderr), &failure)
		if !exited || failure.Error.Code != errCodeFolderNotFound || failure.Error.StatusCode != http.StatusNotFound || failure.Error.RequestID != "req-gone" {
			t.Errorf("%s: exited=%v stderr=%s", args[0], exited, stderr)
		}
	}
}

func TestFoldersEmptyTipTargetsWhereYouLooked(t *testing.T) {
	stderr, _, exited := runFolders(t, &fakeFoldersAPI{}, "get", "--env", "staging", "--path", "/nothing", "--projectId", testProjectID)
	want := "[infisical secrets-manager folders create <name> --path /nothing --env staging --projectId " + testProjectID + "]"
	if exited || !strings.Contains(stderr, want) {
		t.Errorf("exited=%v stderr=%s want %s", exited, stderr, want)
	}
}
