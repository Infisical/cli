package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
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

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{})
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

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{Dir: dir, Symlink: func(string, string) error { linked = true; return nil }})
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
		"no skills route": func() *agentVaultSkillsClient { return fakeSessionSkills(t, http.StatusNotFound, routeMissingBody) },
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
		installAgentVaultRunSkills(context.Background(), client(), agentvault.InstallOptions{})
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
	_, err = fakeSessionSkills(t, http.StatusForbidden, map[string]any{"message": "You are not allowed to read skills."}).list(context.Background())
	if got, want := agentVaultSkillsFailureReason(err), "Infisical answered 403: You are not allowed to read skills"; got != want {
		t.Fatalf("reason %q, want %q", got, want)
	}
}

func TestTheInstalledLineNamesTheLinkedFolders(t *testing.T) {
	claude := agentvault.LinkedAgent{Agent: agentvault.ClaudeCodeAgent, Dir: "/h/.claude/skills"}
	hermes := agentvault.LinkedAgent{Agent: agentvault.HermesAgent, Dir: "/h/.hermes/skills"}
	cases := []struct {
		result agentvault.InstallResult
		want   string
	}{
		{agentvault.InstallResult{Dir: "/h/.agents/skills", Installed: 1}, "Installed 1 skill in /h/.agents/skills."},
		{agentvault.InstallResult{Dir: "/s", Installed: 3, Linked: []agentvault.LinkedAgent{claude}}, "Installed 3 skills in /s (linked in /h/.claude/skills)."},
		{agentvault.InstallResult{Dir: "/s", Installed: 2, Linked: []agentvault.LinkedAgent{hermes}}, "Installed 2 skills in /s (linked in /h/.hermes/skills)."},
		{
			agentvault.InstallResult{Dir: "/s", Installed: 2, Linked: []agentvault.LinkedAgent{claude, hermes}},
			"Installed 2 skills in /s (linked in /h/.claude/skills and /h/.hermes/skills).",
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
			installAgentVaultRunSkills(stepCtx, client, agentvault.InstallOptions{})
			interrupt()
		},
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
		func(stepCtx context.Context) {
			installAgentVaultRunSkills(stepCtx, client, agentvault.InstallOptions{})
		},
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
		func(stepCtx context.Context) {
			installAgentVaultRunSkills(stepCtx, client, agentvault.InstallOptions{})
		},
		func() { t.Fatal("revoked without an interrupt") })
	if interrupted || !exists(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")) {
		t.Fatalf("interrupted %v", interrupted)
	}
}

func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := util.GetStderrWriter
	util.GetStderrWriter = func() io.Writer { return &buf }
	t.Cleanup(func() { util.GetStderrWriter = old })
	return &buf
}

func TestAMissingRouteNamesTheDomain(t *testing.T) {
	isolateSkillsHome(t)
	plainBody := map[string]any{"statusCode": 404, "error": "Not Found", "message": "Route GET:/api/v1/agent-vault/session/skills not found"}
	for name, body := range map[string]map[string]any{"with documentationUrl": routeMissingBody, "Fastify's default": plainBody} {
		t.Run(name, func(t *testing.T) {
			warnings := captureWarnings(t)
			client := fakeSessionSkills(t, http.StatusNotFound, body)
			if _, err := client.list(context.Background()); !isInfisicalRouteMissing(err) {
				t.Fatalf("not read as a missing route: %v", err)
			}
			installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{})
			want := "Starting without skills: " + strings.TrimSuffix(config.INFISICAL_URL, "/api") + " doesn't provide them. Check --domain."
			if !strings.Contains(warnings.String(), want) || strings.Contains(warnings.String(), "/api ") {
				t.Fatalf("warned %q, want %q", warnings.String(), want)
			}
		})
	}
}

func TestTheSessionWarningUsesInfisicalsMessage(t *testing.T) {
	isolateSkillsHome(t)
	for _, tc := range []struct {
		body map[string]any
		want string
	}{
		{sessionInvalidBody, "Starting without skills: Invalid session."},
		{map[string]any{"statusCode": 401, "error": "UnauthorizedError", "message": "Session expired."}, "Starting without skills: Session expired."},
		{map[string]any{"statusCode": 401, "error": "UnauthorizedError"}, "Starting without skills: the session is no longer valid."},
	} {
		warnings := captureWarnings(t)
		installAgentVaultRunSkills(context.Background(), fakeSessionSkills(t, http.StatusUnauthorized, tc.body), agentvault.InstallOptions{})
		if !strings.Contains(warnings.String(), tc.want) {
			t.Fatalf("warned %q, want %q", warnings.String(), tc.want)
		}
	}
}

// Answers 401 to the first unauthorized requests, then lists the skill.
func fakeSessionSkillsAfter401s(t *testing.T, unauthorized int, skill api.AgentVaultSessionSkill) (*agentVaultSkillsClient, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if int(requests.Add(1)) <= unauthorized {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(sessionInvalidBody)
			return
		}
		_ = json.NewEncoder(w).Encode(api.ListAgentVaultSessionSkillsResponse{Skills: []api.AgentVaultSessionSkill{skill}})
	}))
	t.Cleanup(srv.Close)
	useInfisicalURL(t, srv.URL+"/api")
	old := agentVaultSkillsUnauthorizedRetryDelays
	agentVaultSkillsUnauthorizedRetryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { agentVaultSkillsUnauthorizedRetryDelays = old })
	return &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}, &requests
}

func TestAMintedRunRetriesASessionNotFoundYet(t *testing.T) {
	home := isolateSkillsHome(t)
	client, requests := fakeSessionSkillsAfter401s(t, 2, testSessionSkill("code-review", "x"))
	client.retryUnauthorized = true

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{})
	if requests.Load() != 3 || !exists(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")) {
		t.Fatalf("%d requests, skill installed %v", requests.Load(), exists(filepath.Join(home, ".agents", "skills", "code-review")))
	}
}

func TestAMintedRunStopsRetryingAfterTwo(t *testing.T) {
	isolateSkillsHome(t)
	client, requests := fakeSessionSkillsAfter401s(t, 3, testSessionSkill("code-review", "x"))
	client.retryUnauthorized = true

	if _, err := client.list(context.Background()); !isAgentVaultSessionInvalid(err) || requests.Load() != 3 {
		t.Fatalf("%d requests, err %v", requests.Load(), err)
	}
}

func TestASessionTokenRunDoesNotRetry(t *testing.T) {
	home := isolateSkillsHome(t)
	client, requests := fakeSessionSkillsAfter401s(t, 1, testSessionSkill("code-review", "x"))

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{})
	if requests.Load() != 1 || exists(filepath.Join(home, ".agents")) {
		t.Fatalf("%d requests", requests.Load())
	}
}

func TestSkillsAreLinkedForClaudeWhenItIsTheAgent(t *testing.T) {
	home := isolateSkillsHome(t)
	client := fakeSessionSkills(t, http.StatusOK, nil, testSessionSkill("code-review", "x"))

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{ForceClaude: agentVaultRunStartsClaude([]string{"/usr/local/bin/claude", "--resume"})})
	assertRunLinked(t, filepath.Join(home, ".claude", "skills", "code-review"), filepath.Join(home, ".agents", "skills", "code-review"))
}

func assertRunLinked(t *testing.T, link, target string) {
	t.Helper()
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Fatalf("%s: %s, %v", link, got, err)
	}
}

func TestAgentVaultRunStartsClaude(t *testing.T) {
	for agent, want := range map[string]bool{
		"claude": true, "/opt/bin/claude": true, "claude.exe": true, "claude.cmd": true, "claude.bat": true,
		"codex": false, "claude-code": false, "hermes": false,
	} {
		if got := agentVaultRunStartsClaude([]string{agent}); got != want {
			t.Errorf("%s: %v, want %v", agent, got, want)
		}
	}
}

func skillsFlagsCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "run", Run: func(*cobra.Command, []string) {}}
	cmd.Flags().String("skills-dir", "", "")
	cmd.Flags().Bool("no-skills", false, "")
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestResolveAgentVaultRunSkills(t *testing.T) {
	dir, skip, err := resolveAgentVaultRunSkills(skillsFlagsCmd(t, "--skills-dir", "./skills"))
	if err != nil || dir != "./skills" || skip {
		t.Fatalf("dir %q, skip %v, err %v", dir, skip, err)
	}
	if _, skip, err = resolveAgentVaultRunSkills(skillsFlagsCmd(t, "--no-skills")); err != nil || !skip {
		t.Fatalf("skip %v, err %v", skip, err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"~":           home,
		"~/skills":    filepath.Join(home, "skills"),
		"~other/x":    "~other/x",
		"./~/skills":  "./~/skills",
		"/abs/skills": "/abs/skills",
	} {
		if dir, _, err = resolveAgentVaultRunSkills(skillsFlagsCmd(t, "--skills-dir", in)); err != nil || dir != want {
			t.Fatalf("%q: dir %q, err %v, want %q", in, dir, err, want)
		}
	}

	_, _, err = resolveAgentVaultRunSkills(skillsFlagsCmd(t, "--skills-dir", " "))
	want := "--skills-dir was given but is empty; pass a folder, or drop the flag to install into ~/.agents/skills"
	if err == nil || err.Error() != want {
		t.Fatalf("err %v, want %q", err, want)
	}
	_, _, err = resolveAgentVaultRunSkills(skillsFlagsCmd(t, "--no-skills", "--skills-dir", "./skills"))
	want = "--skills-dir was given with --no-skills, which installs no skills; drop one of the two"
	if err == nil || err.Error() != want {
		t.Fatalf("err %v, want %q", err, want)
	}
}

func TestNoSkillsMakesNoRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer srv.Close()
	useInfisicalURL(t, srv.URL+"/api")
	client := &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}

	_, interrupted := runAgentVaultRunSkillsStep(true,
		func(ctx context.Context) { installAgentVaultRunSkills(ctx, client, agentvault.InstallOptions{}) },
		func(context.Context) { t.Fatal("revoked") })
	if interrupted || requests.Load() != 0 {
		t.Fatalf("interrupted %v, %d requests", interrupted, requests.Load())
	}
}

func TestASkillsStepThatTimesOutStillStartsTheAgent(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	old := agentVaultSkillsTimeout
	agentVaultSkillsTimeout = 100 * time.Millisecond
	t.Cleanup(func() { agentVaultSkillsTimeout = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	useInfisicalURL(t, srv.URL+"/api")
	client := &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok", retryUnauthorized: true}

	_, interrupted := runAgentVaultRunSkillsStep(false,
		func(ctx context.Context) { installAgentVaultRunSkills(ctx, client, agentvault.InstallOptions{}) },
		func(context.Context) { t.Fatal("revoked after a timeout") })
	if interrupted {
		t.Fatal("a timeout was taken for an interrupt")
	}
	if want := "Starting without skills: Infisical did not send them within 100ms. Pass --no-skills if this host can't reach Infisical."; !strings.Contains(warnings.String(), want) {
		t.Fatalf("warned %q, want %q", warnings.String(), want)
	}
}

func TestAnUnreachableInfisicalNamesTheFlag(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	useInfisicalURL(t, "http://127.0.0.1:1/api")
	client := &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{})
	got := strings.TrimSpace(warnings.String())
	if !strings.Contains(got, "Starting without skills: CallListAgentVaultSessionSkills: ") || !strings.HasSuffix(got, ". Pass --no-skills if this host can't reach Infisical.") {
		t.Fatalf("warned %q", got)
	}
}

func TestAnInfisicalErrorDoesNotNameTheFlag(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	installAgentVaultRunSkills(context.Background(), fakeSessionSkills(t, http.StatusInternalServerError, map[string]any{"message": "boom"}), agentvault.InstallOptions{})
	if got := strings.TrimSpace(warnings.String()); !strings.HasSuffix(got, "Starting without skills: Infisical answered 500: boom.") {
		t.Fatalf("warned %q", got)
	}
}

func TestTheSkillsClientGivesUpOnAConnectionEarly(t *testing.T) {
	old := agentVaultSkillsConnectTimeout
	agentVaultSkillsConnectTimeout = 100 * time.Millisecond
	t.Cleanup(func() { agentVaultSkillsConnectTimeout = old })
	t.Setenv(util.INFISICAL_RETRY_MAX_RETRIES_NAME, "0")
	client, err := newAgentVaultSkillsHTTPClient()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	// A non-routable address, so the dial hangs until the connect timeout unless the network refuses it first.
	_, err = client.R().SetContext(ctx).Get("http://10.255.255.1:81/")
	if err == nil {
		t.Fatal("want an error")
	}
	if ctx.Err() != nil || time.Since(start) > 5*time.Second {
		t.Fatalf("the connection was not given up early: %v after %s", err, time.Since(start))
	}
}

func TestAgentVaultSignalExitCode(t *testing.T) {
	for sig, want := range map[os.Signal]int{syscall.SIGINT: 130, syscall.SIGTERM: 143, syscall.SIGHUP: 129, syscall.SIGQUIT: 131} {
		if got := agentVaultSignalExitCode(sig); got != want {
			t.Errorf("%v: %d, want %d", sig, got, want)
		}
	}
}

func TestASecondSignalCutsTheRevokeShortWithItsWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals cannot be sent to this process here")
	}
	warnings := captureWarnings(t)
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = self.Signal(syscall.SIGTERM)
		<-r.Context().Done()
	}))
	defer srv.Close()
	useInfisicalURL(t, srv.URL+"/api")
	t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME, "")
	t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET_NAME, "")
	t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "")
	t.Setenv(util.INFISICAL_TOKEN_NAME, "identity-token")
	cmd := &cobra.Command{}
	cmd.Flags().String("client-id", "", "")
	cmd.Flags().String("client-secret", "", "")
	minted := &api.AgentVaultSession{ID: testRunSkillID}

	start := time.Now()
	exitCode, interrupted := runAgentVaultRunSkillsStep(false,
		func(ctx context.Context) {
			_ = self.Signal(syscall.SIGINT)
			<-ctx.Done()
		},
		func(ctx context.Context) {
			revokeAgentVaultRunSession(ctx, cmd, minted, false, "The run was interrupted", true)
		})
	if !interrupted || exitCode != 143 {
		t.Fatalf("interrupted %v, exit code %d", interrupted, exitCode)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("the second signal did not cut the revoke short: %s", waited)
	}
	if want := "The run was interrupted but its session could not be revoked ("; !strings.Contains(warnings.String(), want) || !strings.Contains(warnings.String(), "Revoke it in Infisical.") {
		t.Fatalf("warned %q", warnings.String())
	}
}
