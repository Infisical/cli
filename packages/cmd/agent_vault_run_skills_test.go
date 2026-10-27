package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

const testRunSkillID = "8f0e7c1a-3b9e-4c55-9d3e-2a1b7c6d5e4f"

func testSessionSkill(name, content string) api.AgentVaultSessionSkill {
	files := []api.AgentVaultSkillFile{{Path: "SKILL.md", Mode: "0644", ContentBase64: base64.StdEncoding.EncodeToString([]byte(content))}}
	return api.AgentVaultSessionSkill{ID: testRunSkillID, Name: name, Version: 1, Sha256: agentvault.SkillFilesSha256(files), Files: files}
}

// A stand-in for Infisical's session skills route. A status other than 200 answers with body.
func fakeSessionSkills(t *testing.T, status int, body map[string]any, skills ...api.AgentVaultSessionSkill) *agentVaultSkillsClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent-vault/session/skills" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer agv_tok" {
			t.Errorf("the session token was not sent as a bearer token: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		_ = json.NewEncoder(w).Encode(api.ListAgentVaultSessionSkillsResponse{Skills: skills})
	}))
	t.Cleanup(srv.Close)
	useInfisicalURL(t, srv.URL+"/api")
	return &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}
}

func useInfisicalURL(t *testing.T, url string) {
	t.Helper()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = url
	t.Cleanup(func() { config.INFISICAL_URL = old })
}

var (
	routeMissingBody = map[string]any{
		"statusCode": 404, "error": "Not Found", "message": "Route GET:/api/v1/agent-vault/session/skills not found",
		"documentationUrl": "https://infisical.com/docs",
	}
	handlerNotFoundBody = map[string]any{"statusCode": 404, "error": "NotFound", "message": "Project not found"}
	sessionInvalidBody  = map[string]any{"statusCode": 401, "error": "UnauthorizedError", "message": "Invalid session"}
)

func isolateSkillsHome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the home folder is not HOME here")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("HERMES_HOME", "")
	return home
}

func TestSkillsAreInstalledInTheHomeFolderAndLinkedForClaude(t *testing.T) {
	home := isolateSkillsHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	client := fakeSessionSkills(t, http.StatusOK, nil, testSessionSkill("code-review", "---\nname: code-review\n---\n"))

	installAgentVaultRunSkills(context.Background(), "", client, os.Symlink)
	canonical := filepath.Join(home, ".agents", "skills", "code-review")
	if _, err := os.Stat(filepath.Join(canonical, "SKILL.md")); err != nil {
		t.Fatalf("the skill was not written before start: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(home, ".claude", "skills", "code-review")); err != nil || target != canonical {
		t.Fatalf("the skill was not linked for Claude Code: %s, %v", target, err)
	}
}

func TestSkillsDirInstallsThereWithoutLinks(t *testing.T) {
	home := isolateSkillsHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "skills")
	client := fakeSessionSkills(t, http.StatusOK, nil, testSessionSkill("code-review", "x"))
	linked := false

	installAgentVaultRunSkills(context.Background(), dir, client, func(string, string) error { linked = true; return nil })
	if _, err := os.Stat(filepath.Join(dir, "code-review", "SKILL.md")); err != nil {
		t.Fatalf("the skill was not written: %v", err)
	}
	if linked || exists(filepath.Join(home, ".claude", "skills")) || exists(filepath.Join(home, ".agents")) {
		t.Fatal("a chosen folder still wrote to the home folder")
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestTheAgentStartsPlainlyWithoutSkills(t *testing.T) {
	home := isolateSkillsHome(t)
	cases := map[string]func() *agentVaultSkillsClient{
		"Infisical too old": func() *agentVaultSkillsClient { return fakeSessionSkills(t, http.StatusNotFound, routeMissingBody) },
		"session gone": func() *agentVaultSkillsClient {
			return fakeSessionSkills(t, http.StatusUnauthorized, sessionInvalidBody)
		},
		"Infisical failing": func() *agentVaultSkillsClient {
			return fakeSessionSkills(t, http.StatusInternalServerError, map[string]any{})
		},
		"no skills": func() *agentVaultSkillsClient { return fakeSessionSkills(t, http.StatusOK, nil) },
		"Infisical is unreachable": func() *agentVaultSkillsClient {
			useInfisicalURL(t, "http://127.0.0.1:1/api")
			return &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}
		},
	}
	for name, client := range cases {
		installAgentVaultRunSkills(context.Background(), "", client(), os.Symlink)
		if exists(filepath.Join(home, ".agents")) {
			t.Fatalf("%s: a skills folder was created", name)
		}
	}
}

func TestSkillsFailuresAreToldApart(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		body         map[string]any
		routeMissing bool
		invalid      bool
	}{
		{name: "route missing", status: http.StatusNotFound, body: routeMissingBody, routeMissing: true},
		{name: "a handler's not found", status: http.StatusNotFound, body: handlerNotFoundBody},
		{name: "session invalid", status: http.StatusUnauthorized, body: sessionInvalidBody, invalid: true},
		{name: "server error", status: http.StatusInternalServerError, body: map[string]any{"message": "boom"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fakeSessionSkills(t, tc.status, tc.body).list(context.Background())
			if err == nil {
				t.Fatal("want an error")
			}
			if got := isInfisicalRouteMissing(err); got != tc.routeMissing {
				t.Errorf("route missing = %v, want %v", got, tc.routeMissing)
			}
			if got := isAgentVaultSessionInvalid(err); got != tc.invalid {
				t.Errorf("session invalid = %v, want %v", got, tc.invalid)
			}
		})
	}
}

func TestSkillsFailureReasonNamesInfisicalsAnswer(t *testing.T) {
	_, err := fakeSessionSkills(t, http.StatusInternalServerError, map[string]any{"message": "boom"}).list(context.Background())
	if got, want := agentVaultSkillsFailureReason(err), "Infisical answered 500: boom"; got != want {
		t.Fatalf("reason %q, want %q", got, want)
	}
}

func TestTheInstalledLineNamesOnlyTheLinkedAgents(t *testing.T) {
	cases := []struct {
		result agentvault.InstallResult
		want   string
	}{
		{agentvault.InstallResult{Dir: "/h/.agents/skills", Installed: 1}, "Installed 1 skill in /h/.agents/skills."},
		{agentvault.InstallResult{Dir: "/s", Installed: 3, Linked: []string{agentvault.ClaudeCodeAgent}}, "Installed 3 skills in /s (linked for Claude Code)."},
		{agentvault.InstallResult{Dir: "/s", Installed: 2, Linked: []string{agentvault.HermesAgent}}, "Installed 2 skills in /s (linked for Hermes)."},
		{
			agentvault.InstallResult{Dir: "/s", Installed: 2, Linked: []string{agentvault.ClaudeCodeAgent, agentvault.HermesAgent}},
			"Installed 2 skills in /s (linked for Claude Code and Hermes).",
		},
	}
	for _, tc := range cases {
		if got := agentVaultSkillsInstalledLine(tc.result); got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}
}

func TestInterruptingTheSkillsStepRevokes(t *testing.T) {
	home := isolateSkillsHome(t)
	client := fakeSessionSkills(t, http.StatusOK, nil, testSessionSkill("code-review", "x"))

	ctx, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	revoked := 0
	interrupted := prepareAgentVaultRunSkills(ctx,
		func(stepCtx context.Context) {
			installAgentVaultRunSkills(stepCtx, "", client, os.Symlink)
			interrupt()
		},
		func() {},
		func() { revoked++ })
	if !interrupted || revoked != 1 {
		t.Fatalf("interrupted %v, revoked %d times", interrupted, revoked)
	}
	if !exists(filepath.Join(home, ".agents", "skills", "code-review")) {
		t.Fatal("an installed skill was removed")
	}
}

func TestInterruptingAWaitForInfisicalRevokes(t *testing.T) {
	isolateSkillsHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	useInfisicalURL(t, srv.URL+"/api")
	client := &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}

	ctx, interrupt := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, interrupt)
	revoked := false
	start := time.Now()
	interrupted := prepareAgentVaultRunSkills(ctx,
		func(stepCtx context.Context) { installAgentVaultRunSkills(stepCtx, "", client, os.Symlink) },
		func() {},
		func() { revoked = true })
	if !interrupted || !revoked {
		t.Fatalf("interrupted %v, revoked %v", interrupted, revoked)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the interrupt did not cut the wait short")
	}
}

func TestAnUninterruptedSkillsStepDoesNotRevoke(t *testing.T) {
	home := isolateSkillsHome(t)
	client := fakeSessionSkills(t, http.StatusOK, nil, testSessionSkill("code-review", "x"))
	interrupted := prepareAgentVaultRunSkills(context.Background(),
		func(stepCtx context.Context) { installAgentVaultRunSkills(stepCtx, "", client, os.Symlink) },
		func() { t.Fatal("signals stopped without an interrupt") },
		func() { t.Fatal("revoked without an interrupt") })
	if interrupted || !exists(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")) {
		t.Fatalf("interrupted %v", interrupted)
	}
}

func TestAnInterruptStopsSignalsBeforeRevoking(t *testing.T) {
	ctx, interrupt := context.WithCancel(context.Background())
	var order []string
	interrupted := prepareAgentVaultRunSkills(ctx,
		func(context.Context) { interrupt() },
		func() { order = append(order, "stop signals") },
		func() { order = append(order, "revoke") })
	if !interrupted || !reflect.DeepEqual(order, []string{"stop signals", "revoke"}) {
		t.Fatalf("interrupted %v, order %v", interrupted, order)
	}
}
