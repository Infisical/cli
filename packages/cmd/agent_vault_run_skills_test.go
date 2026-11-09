package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
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

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, false)
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

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{Dir: dir, Symlink: func(string, string) error { linked = true; return nil }}, false)
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
		installAgentVaultRunSkills(context.Background(), client(), agentvault.InstallOptions{}, false)
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
	interrupted := prepareAgentVaultRunStartup(ctx,
		func(stepCtx context.Context) {
			installAgentVaultRunSkills(stepCtx, client, agentvault.InstallOptions{}, false)
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
	interrupted := prepareAgentVaultRunStartup(ctx,
		func(stepCtx context.Context) {
			installAgentVaultRunSkills(stepCtx, client, agentvault.InstallOptions{}, false)
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
	interrupted := prepareAgentVaultRunStartup(context.Background(),
		func(stepCtx context.Context) {
			installAgentVaultRunSkills(stepCtx, client, agentvault.InstallOptions{}, false)
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
			installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, false)
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
		installAgentVaultRunSkills(context.Background(), fakeSessionSkills(t, http.StatusUnauthorized, tc.body), agentvault.InstallOptions{}, false)
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

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, false)
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

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, false)
	if requests.Load() != 1 || exists(filepath.Join(home, ".agents")) {
		t.Fatalf("%d requests", requests.Load())
	}
}

func TestSkillsAreLinkedForClaudeWhenItIsTheAgent(t *testing.T) {
	home := isolateSkillsHome(t)
	client := fakeSessionSkills(t, http.StatusOK, nil, testSessionSkill("code-review", "x"))

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{ForceClaude: agentVaultRunStartsClaude([]string{"/usr/local/bin/claude", "--resume"})}, false)
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

// With --no-skills nothing is installed and Infisical isn't asked; the proxy is asked once, for headers only, so the agent
// still gets the API URL once an answer from inside TLS confirms it.
func TestNoSkillsOnlyConfirmsTheAPIURL(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer srv.Close()
	useInfisicalURL(t, srv.URL+"/api")
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusOK, skillsBody())

	var apiURL string
	_, interrupted := runAgentVaultRunStartupStep(
		func(ctx context.Context) {
			apiURL = prepareAgentVaultRunProxy(ctx, proxy.addr, "agv_tok", proxy.caPEM, false, nil)
		},
		func(context.Context) { t.Fatal("revoked") })
	if interrupted || requests.Load() != 0 || apiURL != testProxyAPIURL {
		t.Fatalf("interrupted %v, %d requests to Infisical, API URL %q", interrupted, requests.Load(), apiURL)
	}
	if proxy.requests.Load() != 1 || proxy.lastRequest.Load() != "HEAD /api/v1/agent-vault/session/services" {
		t.Fatalf("the proxy saw %d requests, the last %v", proxy.requests.Load(), proxy.lastRequest.Load())
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
	proxy := newFakeTunnelProxy(t, "old", 0, nil)

	_, interrupted := runAgentVaultRunStartupStep(
		func(ctx context.Context) {
			prepareAgentVaultRunProxy(ctx, proxy.addr, "agv_tok", proxy.caPEM, false, func(ctx context.Context, _ *agentVaultSkillsTunnel, _ bool) {
				installAgentVaultRunSkills(ctx, client, agentvault.InstallOptions{}, false)
			})
		},
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

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, false)
	got := strings.TrimSpace(warnings.String())
	if !strings.Contains(got, "Starting without skills: CallListAgentVaultSessionSkills: ") || !strings.HasSuffix(got, ". Pass --no-skills if this host can't reach Infisical.") {
		t.Fatalf("warned %q", got)
	}
}

func TestAnInfisicalErrorDoesNotNameTheFlag(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	installAgentVaultRunSkills(context.Background(), fakeSessionSkills(t, http.StatusInternalServerError, map[string]any{"message": "boom"}), agentvault.InstallOptions{}, false)
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
	// An HTTP_PROXY would answer for the address itself, so the dial under test would never happen.
	transport, err := client.Transport()
	if err != nil {
		t.Fatal(err)
	}
	transport.Proxy = nil

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	// TEST-NET-1 (RFC 5737) is reserved for documentation, so no network answers it: the dial hangs until the
	// connect timeout unless the network refuses it first.
	_, err = client.R().SetContext(ctx).Get("http://192.0.2.1:81/")
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
	exitCode, interrupted := runAgentVaultRunStartupStep(
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

func TestASessionTokenIsNotSentToTheDomainInARepoFile(t *testing.T) {
	isolateSkillsHome(t)
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".infisical.json"), []byte(`{"domain":"https://evil.example"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	useInfisicalURL(t, "https://evil.example/api")
	old := config.INFISICAL_DOMAIN_EXPLICITLY_SET
	config.INFISICAL_DOMAIN_EXPLICITLY_SET = false
	t.Cleanup(func() { config.INFISICAL_DOMAIN_EXPLICITLY_SET = old })

	useAgentVaultSessionTokenDomain()
	if config.INFISICAL_URL != "https://app.infisical.com/api" {
		t.Fatalf("the token would go to %s", config.INFISICAL_URL)
	}
}

func TestASessionTokenGoesToAnExplicitDomain(t *testing.T) {
	isolateSkillsHome(t)
	useInfisicalURL(t, "https://eu.infisical.com/api")
	old := config.INFISICAL_DOMAIN_EXPLICITLY_SET
	config.INFISICAL_DOMAIN_EXPLICITLY_SET = true
	t.Cleanup(func() { config.INFISICAL_DOMAIN_EXPLICITLY_SET = old })

	useAgentVaultSessionTokenDomain()
	if config.INFISICAL_URL != "https://eu.infisical.com/api" {
		t.Fatalf("the token would go to %s", config.INFISICAL_URL)
	}
}

func TestTheSkillsClientAsksABusyInfisicalAgain(t *testing.T) {
	var requests atomic.Int32
	skill := testSessionSkill("code-review", "x")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{})
			return
		}
		_ = json.NewEncoder(w).Encode(api.ListAgentVaultSessionSkillsResponse{Skills: []api.AgentVaultSessionSkill{skill}})
	}))
	defer srv.Close()
	useInfisicalURL(t, srv.URL+"/api")
	t.Setenv(util.INFISICAL_RETRY_BASE_DELAY_NAME, "10ms")
	httpClient, err := newAgentVaultSkillsHTTPClient()
	if err != nil {
		t.Fatal(err)
	}

	listed, err := (&agentVaultSkillsClient{httpClient: httpClient, sessionToken: "agv_tok"}).list(context.Background())
	if err != nil || len(listed.Skills) != 1 || requests.Load() != 2 {
		t.Fatalf("err %v, skills %d, requests %d", err, len(listed.Skills), requests.Load())
	}
}

// The Infisical the fake proxy names, which tunnels to it reach through the proxy.
const testProxyAPIURL = "https://infisical.test/api"

// The Infisical the fake proxy names in "http" mode, as for a --domain without TLS.
const testHTTPProxyAPIURL = "http://infisical.test:8080/api"

// A stand-in for an Agent Vault proxy. "forwards" names its Infisical on every CONNECT and again inside TLS, and answers
// for the session the way a proxy that forwards to Infisical does, marked; "busy-once" answers its first request the way
// a proxy with no free slot does, then forwards; "http" forwards for an Infisical whose --domain is http; "rewritten"
// forwards, but its CONNECT answer reaches the client changed on the way to an http URL; "cut" forwards, but cuts the
// skills answer short after its headers; "refuses" turns the CONNECT down, and "old" opens it, the way an older proxy
// does, neither naming an Infisical.
type fakeTunnelProxy struct {
	addr           string
	caPEM          []byte
	sessionToken   atomic.Value
	includeBuiltin atomic.Value
	// The method and path of the last request that reached the proxy through a tunnel.
	lastRequest atomic.Value
	// The Authorization header of every request that reached the proxy through a tunnel, which must be empty: the proxy
	// adds the session's token itself.
	authorizations atomic.Value
	// Requests that reached the proxy through a tunnel.
	requests atomic.Int32
}

// The URL the fake proxy's CONNECT answer claims and the one it names inside TLS, by mode.
func fakeTunnelProxyAPIURLs(mode string) (claimed, named string) {
	switch mode {
	case "forwards", "busy-once", "cut":
		return testProxyAPIURL, testProxyAPIURL
	case "http":
		return testHTTPProxyAPIURL, testHTTPProxyAPIURL
	case "rewritten":
		return "http://infisical.test/api", testProxyAPIURL
	case "redirects":
		return testProxyAPIURL, ""
	}
	return "", ""
}

func newFakeTunnelProxy(t *testing.T, mode string, status int, body any) *fakeTunnelProxy {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "infisical.test"},
		DNSNames:              []string{"infisical.test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	proxy := &fakeTunnelProxy{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	proxy.addr = listener.Addr().String()

	serve := func(conn net.Conn) {
		defer conn.Close()
		connect, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		if user, password, ok := (&http.Request{Header: http.Header{"Authorization": connect.Header["Proxy-Authorization"]}}).BasicAuth(); ok && user == agentvault.ProxyAuthUsername {
			proxy.sessionToken.Store(password)
		}
		if mode == "refuses" {
			_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			return
		}
		claimed, named := fakeTunnelProxyAPIURLs(mode)
		established := "HTTP/1.1 200 Connection Established\r\n"
		if claimed != "" {
			established += agentvault.HeaderAPIURL + ": " + claimed + "\r\n"
		}
		_, _ = io.WriteString(conn, established+"\r\n")
		inner := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		req, err := http.ReadRequest(bufio.NewReader(inner))
		if err != nil {
			return
		}
		proxy.includeBuiltin.Store(req.URL.Query().Get("includeBuiltin"))
		proxy.lastRequest.Store(req.Method + " " + req.URL.Path)
		if authorization := req.Header.Get("Authorization"); authorization != "" {
			proxy.authorizations.Store(authorization)
		}
		seen := proxy.requests.Add(1)
		rec := httptest.NewRecorder()
		rec.Header().Set("Connection", "close")
		if named != "" {
			rec.Header().Set(agentvault.HeaderAPIURL, named)
		}
		decision := agentvault.DecisionSkills
		if strings.HasSuffix(req.URL.Path, "/session/services") {
			decision = agentvault.DecisionDiscovery
		}
		if mode == "cut" && decision == agentvault.DecisionSkills {
			_, _ = io.WriteString(inner, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n"+
				agentvault.HeaderDecision+": skills\r\n"+agentvault.HeaderAPIURL+": "+named+"\r\n\r\n{\"skills\":[")
			return
		}
		if mode == "redirects" {
			// A host's redirect, passed on as passthrough, and forged headers for whatever the redirect leads to.
			if seen == 1 {
				rec.Header().Set(agentvault.HeaderDecision, "passthrough")
				rec.Header().Set("Location", testProxyAPIURL+"/v1/agent-vault/session/skills?followed=1")
				rec.WriteHeader(http.StatusFound)
			} else {
				rec.Header().Set(agentvault.HeaderAPIURL, testProxyAPIURL)
				rec.Header().Set(agentvault.HeaderDecision, decision)
				rec.Header().Set("Content-Type", "application/json")
				rec.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(rec).Encode(body)
			}
		} else if mode == "busy-once" && seen == 1 {
			rec.Header().Set(agentvault.HeaderDecision, "error")
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(rec, `{"error":"busy","message":"too many agents are starting through the proxy at once"}`)
		} else if named != "" {
			rec.Header().Set(agentvault.HeaderDecision, decision)
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(status)
			if req.Method != http.MethodHead {
				_ = json.NewEncoder(rec).Encode(body)
			}
		} else {
			rec.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(rec, "failed to reach the upstream")
		}
		_ = rec.Result().Write(inner)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()
	return proxy
}

func throughTunnel(t *testing.T, client *agentVaultSkillsClient, proxy *fakeTunnelProxy, askedDirectly *bool) *agentVaultSkillsClient {
	t.Helper()
	tunnel, err := newAgentVaultSkillsTunnel(proxy.addr, client.sessionToken, testProxyAPIURL, proxy.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	client.tunnel = tunnel
	client.includeBuiltin = true
	client.beforeDirect = func() { *askedDirectly = true }
	return client
}

func skillsBody(skills ...api.AgentVaultSessionSkill) api.ListAgentVaultSessionSkillsResponse {
	return api.ListAgentVaultSessionSkillsResponse{Skills: skills}
}

func TestRunGetsSkillsThroughTheProxysTunnel(t *testing.T) {
	home := isolateSkillsHome(t)
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusOK, skillsBody(testSessionSkill("code-review", "x")))
	var askedDirectly bool
	client := throughTunnel(t, &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}, proxy, &askedDirectly)

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, true)
	if askedDirectly {
		t.Fatal("asked Infisical directly although the proxy forwarded the request")
	}
	if got := proxy.sessionToken.Load(); got != "agv_tok" {
		t.Fatalf("the tunnel carried session token %v", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")); err != nil {
		t.Fatalf("the skill from the proxy wasn't installed: %v", err)
	}
}

func TestRunAsksTheProxyWhichInfisicalItWorksWith(t *testing.T) {
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusOK, skillsBody())
	if got, answered := askAgentVaultProxyAPIURL(context.Background(), proxy.addr, "agv_tok", false); got != testProxyAPIURL || !answered {
		t.Fatalf("the proxy named %q (answered %v), want %q", got, answered, testProxyAPIURL)
	}
	if got := proxy.sessionToken.Load(); got != "agv_tok" {
		t.Fatalf("the CONNECT carried session token %v", got)
	}
	if got := proxy.requests.Load(); got != 0 {
		t.Fatalf("asking sent %d requests through the tunnel", got)
	}
}

// An older proxy names no Infisical, so the run asks Infisical directly rather than through the proxy.
func TestRunAsksInfisicalDirectlyBehindAProxyThatNamesNoInfisical(t *testing.T) {
	for _, mode := range []string{"refuses", "old"} {
		t.Run(mode, func(t *testing.T) {
			home := isolateSkillsHome(t)
			proxy := newFakeTunnelProxy(t, mode, 0, nil)
			if got, answered := askAgentVaultProxyAPIURL(context.Background(), proxy.addr, "agv_tok", false); got != "" || !answered {
				t.Fatalf("an older proxy named %q (answered %v)", got, answered)
			}
			var askedDirectly bool
			client := fakeSessionSkills(t, http.StatusOK, nil, testSessionSkill("code-review", "x"))
			client.proxyTooOld = true
			client.includeBuiltin = true
			client.beforeDirect = func() { askedDirectly = true }

			installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, true)
			if !askedDirectly || proxy.requests.Load() != 0 {
				t.Fatalf("asked directly %v, through the older proxy %d times", askedDirectly, proxy.requests.Load())
			}
			if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")); err != nil {
				t.Fatalf("the skill from Infisical wasn't installed: %v", err)
			}
		})
	}
}

func TestAnOldProxyAndAnUnreachableInfisicalNameTheProxy(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	useInfisicalURL(t, "http://127.0.0.1:1/api")
	var askedDirectly bool
	client := &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok", proxyTooOld: true,
		beforeDirect: func() { askedDirectly = true }}

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, true)
	want := "The proxy is too old to pass skills on, so this host asked Infisical directly. Update the Infisical CLI that runs the proxy, or pass --no-skills."
	if got := strings.TrimSpace(warnings.String()); !askedDirectly || !strings.Contains(got, "Starting without skills: CallListAgentVaultSessionSkills: ") || !strings.HasSuffix(got, want) {
		t.Fatalf("warned %q", got)
	}
}

func TestTheProxysOwnRefusalIsNotPutOnInfisical(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	t.Setenv(util.INFISICAL_RETRY_BASE_DELAY_NAME, "10ms")
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusBadGateway,
		map[string]any{"error": "infisical_unreachable", "message": "the proxy could not reach Infisical"})
	var askedDirectly bool
	client := throughTunnel(t, &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}, proxy, &askedDirectly)

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, true)
	if got := strings.TrimSpace(warnings.String()); askedDirectly || !strings.HasSuffix(got, "Starting without skills: the proxy could not reach Infisical.") {
		t.Fatalf("warned %q, asked directly %v", got, askedDirectly)
	}
}

func TestRunTakesInfisicalsRefusalFromTheProxyAsFinal(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusUnauthorized, sessionInvalidBody)
	var askedDirectly bool
	client := throughTunnel(t, &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}, proxy, &askedDirectly)

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, true)
	if askedDirectly {
		t.Fatal("Infisical's own answer, forwarded by the proxy, shouldn't be asked for again")
	}
	if !strings.Contains(warnings.String(), "Starting without skills: Invalid session.") {
		t.Fatalf("warnings: %q", warnings.String())
	}
}

func TestTheProxyRefusingTheSessionReadsAsAnInvalidSession(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusForbidden, map[string]any{
		"error": "session_invalid", "message": "the session is no longer valid, or it belongs to a different Agent Vault project than this proxy",
	})
	var askedDirectly bool
	client := throughTunnel(t, &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}, proxy, &askedDirectly)

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, true)
	if got := warnings.String(); askedDirectly || !strings.Contains(got, "Starting without skills: the session is no longer valid, or it belongs to a different Agent Vault project than this proxy.") {
		t.Fatalf("warned %q, asked directly %v", got, askedDirectly)
	}
}

func TestNoAgentVaultSkillAsksForTheSkillsWithoutIt(t *testing.T) {
	home := isolateSkillsHome(t)
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusOK,
		skillsBody(testSessionSkill(agentvault.BuiltinSkillName, "x"), testSessionSkill("code-review", "x")))
	var askedDirectly bool
	client := throughTunnel(t, &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}, proxy, &askedDirectly)
	client.includeBuiltin = false

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, false)
	if got := proxy.includeBuiltin.Load(); got != "false" {
		t.Fatalf("includeBuiltin = %v, want false", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", agentvault.BuiltinSkillName)); !os.IsNotExist(err) {
		t.Fatalf("the built-in skill was installed despite --no-agent-vault-skill: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")); err != nil {
		t.Fatalf("the other skills should still be installed: %v", err)
	}
}

func TestTheTunnelAsksABusyProxyAgain(t *testing.T) {
	home := isolateSkillsHome(t)
	t.Setenv(util.INFISICAL_RETRY_BASE_DELAY_NAME, "10ms")
	proxy := newFakeTunnelProxy(t, "busy-once", http.StatusOK, skillsBody(testSessionSkill("code-review", "x")))
	var askedDirectly bool
	client := throughTunnel(t, &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}, proxy, &askedDirectly)

	installAgentVaultRunSkills(context.Background(), client, agentvault.InstallOptions{}, true)
	if askedDirectly || proxy.requests.Load() != 2 {
		t.Fatalf("asked the proxy %d times, asked Infisical directly %v", proxy.requests.Load(), askedDirectly)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")); err != nil {
		t.Fatalf("the skill wasn't installed once the proxy had a free slot: %v", err)
	}
}

// A minted run asks again after a refusal, for a session the database hasn't caught up on. Through a proxy, the last try
// has to come after the proxy stops answering the refusal from memory, or every try gets the remembered refusal.
func TestAMintedRunsRetriesOutlastTheProxysMemoryOfARefusal(t *testing.T) {
	var waited time.Duration
	for _, delay := range agentVaultSkillsUnauthorizedRetryDelays {
		waited += delay
	}
	if waited <= agentvault.SessionRefusalTTL {
		t.Fatalf("the retries wait %s in all, not past the %s a proxy remembers a refusal", waited, agentvault.SessionRefusalTTL)
	}
}

// installThrough installs the session's skills with client, through the tunnel prepareAgentVaultRunProxy hands over.
func installThrough(client *agentVaultSkillsClient) func(context.Context, *agentVaultSkillsTunnel, bool) {
	return func(ctx context.Context, tunnel *agentVaultSkillsTunnel, proxyTooOld bool) {
		client.tunnel, client.proxyTooOld, client.includeBuiltin = tunnel, proxyTooOld, true
		installAgentVaultRunSkills(ctx, client, agentvault.InstallOptions{}, true)
	}
}

// silentProxy accepts connections and never answers, like a proxy still waiting on Infisical for the session.
func silentProxy(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, conn); conn.Close() }()
		}
	}()
	return listener.Addr().String()
}

func TestTheAgentGetsTheAPIURLOnceAnAnswerInsideTLSConfirmsIt(t *testing.T) {
	home := isolateSkillsHome(t)
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusOK, skillsBody(testSessionSkill("code-review", "x")))

	apiURL := prepareAgentVaultRunProxy(context.Background(), proxy.addr, "agv_tok", proxy.caPEM, false,
		installThrough(&agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}))
	if apiURL != testProxyAPIURL {
		t.Fatalf("the agent gets %q, want %q", apiURL, testProxyAPIURL)
	}
	if got := proxy.lastRequest.Load(); got != "GET /api/v1/agent-vault/session/skills" {
		t.Fatalf("the proxy saw %v", got)
	}
	if !exists(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")) {
		t.Fatal("the skill from the proxy wasn't installed")
	}
}

// The CONNECT answer crosses the network in the clear. Changed on the way to an http URL, it would have the skills come
// over plain HTTP that anything on the way can forge; the proxy's answer from inside TLS names the URL it really sent.
func TestAnAPIURLChangedOnTheWayIsNotUsed(t *testing.T) {
	home := isolateSkillsHome(t)
	warnings := captureWarnings(t)
	direct := fakeSessionSkills(t, http.StatusOK, nil, testSessionSkill("from-infisical", "x"))
	proxy := newFakeTunnelProxy(t, "rewritten", http.StatusOK, skillsBody(testSessionSkill("from-proxy", "x")))

	apiURL := prepareAgentVaultRunProxy(context.Background(), proxy.addr, "agv_tok", proxy.caPEM, false, installThrough(direct))
	if apiURL != "" {
		t.Fatalf("the agent gets the changed URL %q", apiURL)
	}
	if exists(filepath.Join(home, ".agents", "skills", "from-proxy")) {
		t.Fatal("a skill from the unconfirmed tunnel was installed")
	}
	if !exists(filepath.Join(home, ".agents", "skills", "from-infisical", "SKILL.md")) {
		t.Fatal("the skills weren't taken from Infisical directly instead")
	}
	if !strings.Contains(warnings.String(), "didn't name the Infisical it named on its CONNECT answer") {
		t.Fatalf("warned %q", warnings.String())
	}
}

// An Infisical without TLS is still asked over TLS through the proxy; the fake proxy only speaks TLS in its tunnels.
func TestAnHTTPDomainIsStillAskedOverTLS(t *testing.T) {
	home := isolateSkillsHome(t)
	proxy := newFakeTunnelProxy(t, "http", http.StatusOK, skillsBody(testSessionSkill("code-review", "x")))

	apiURL := prepareAgentVaultRunProxy(context.Background(), proxy.addr, "agv_tok", proxy.caPEM, false,
		installThrough(&agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}))
	if apiURL != testHTTPProxyAPIURL {
		t.Fatalf("the agent gets %q, want %q", apiURL, testHTTPProxyAPIURL)
	}
	if got := proxy.lastRequest.Load(); got != "GET /api/v1/agent-vault/session/skills" {
		t.Fatalf("the proxy saw %v", got)
	}
	if !exists(filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md")) {
		t.Fatal("the skill from the proxy wasn't installed")
	}
}

// A proxy that is still looking the session up hasn't said it is old.
func TestASlowProxyIsNotTakenForAnOldOne(t *testing.T) {
	old := agentVaultProxyAPIURLTimeout
	agentVaultProxyAPIURLTimeout = 100 * time.Millisecond
	t.Cleanup(func() { agentVaultProxyAPIURLTimeout = old })

	called := false
	apiURL := prepareAgentVaultRunProxy(context.Background(), silentProxy(t), "agv_tok", nil, false,
		func(_ context.Context, tunnel *agentVaultSkillsTunnel, proxyTooOld bool) {
			called = true
			if tunnel != nil || proxyTooOld {
				t.Errorf("tunnel %v, too old %v", tunnel, proxyTooOld)
			}
		})
	if !called || apiURL != "" {
		t.Fatalf("installed %v, API URL %q", called, apiURL)
	}
}

// The question to the proxy comes after a minted session, so an interrupt during it revokes the session.
func TestAnInterruptWhileAskingTheProxyRevokes(t *testing.T) {
	addr := silentProxy(t)
	ctx, interrupt := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, interrupt)
	revoked := false
	start := time.Now()

	interrupted := prepareAgentVaultRunStartup(ctx,
		func(ctx context.Context) { prepareAgentVaultRunProxy(ctx, addr, "agv_tok", nil, false, nil) },
		func() { revoked = true })
	if !interrupted || !revoked {
		t.Fatalf("interrupted %v, revoked %v", interrupted, revoked)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the interrupt did not cut the question short")
	}
}

// The skills answer can fail after its headers, such as when it is cut short, and then says nothing about the proxy, so
// the services list confirms the API URL instead of the agent losing it.
func TestASkillsAnswerCutShortStillLeavesTheAgentItsAPIURL(t *testing.T) {
	isolateSkillsHome(t)
	warnings := captureWarnings(t)
	proxy := newFakeTunnelProxy(t, "cut", http.StatusOK, skillsBody())

	apiURL := prepareAgentVaultRunProxy(context.Background(), proxy.addr, "agv_tok", proxy.caPEM, false,
		installThrough(&agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok"}))
	if apiURL != testProxyAPIURL {
		t.Fatalf("the agent gets %q, want %q", apiURL, testProxyAPIURL)
	}
	if got := proxy.lastRequest.Load(); got != "HEAD /api/v1/agent-vault/session/services" {
		t.Fatalf("the proxy last saw %v", got)
	}
	if !strings.Contains(warnings.String(), "Starting without skills:") {
		t.Fatalf("warned %q", warnings.String())
	}
}

// Inside TLS only the proxy can speak, but it passes hosts' answers on, so only an answer it wrote confirms the claim:
// the session endpoint's, or the proxy's own refusal. A host's answer that names the claimed URL is the attack this check
// exists for.
func TestOnlyAnAnswerTheProxyWroteConfirmsTheClaim(t *testing.T) {
	const claimed = "https://infisical.example.com/api"
	answer := func(status int, decision, apiURL string) *resty.Response {
		header := http.Header{}
		if decision != "" {
			header.Set(agentvault.HeaderDecision, decision)
		}
		if apiURL != "" {
			header.Set(agentvault.HeaderAPIURL, apiURL)
		}
		return &resty.Response{RawResponse: &http.Response{StatusCode: status, Header: header}}
	}
	for _, tc := range []struct {
		name                    string
		res                     *resty.Response
		err                     error
		confirmed, contradicted bool
	}{
		{"the endpoint's answer", answer(http.StatusOK, agentvault.DecisionSkills, claimed), nil, true, false},
		{"Infisical's refusal, passed on by the endpoint", answer(http.StatusUnauthorized, agentvault.DecisionSkills, claimed), nil, true, false},
		{"the proxy's own refusal", answer(http.StatusServiceUnavailable, "error", claimed), nil, true, false},
		{"a host's refusal naming the claim", answer(http.StatusUnauthorized, "passthrough", claimed), errAgentVaultProxyAnswerUnconfirmed, false, true},
		{"a host's answer naming the claim", answer(http.StatusOK, "brokered", claimed), errAgentVaultProxyAnswerUnconfirmed, false, true},
		{"another Infisical", answer(http.StatusOK, agentvault.DecisionSkills, "https://evil.example/api"), errAgentVaultProxyAnswerUnconfirmed, false, true},
	} {
		tunnel := &agentVaultSkillsTunnel{claimedAPIURL: claimed}
		err := tunnel.check(tc.res, agentvault.DecisionSkills)
		if !errors.Is(err, tc.err) && err != tc.err || tunnel.confirmed != tc.confirmed || tunnel.contradicted != tc.contradicted {
			t.Errorf("%s: err %v, confirmed %v, contradicted %v", tc.name, err, tunnel.confirmed, tunnel.contradicted)
		}
	}
}

// Until an answer confirms it, the claimed URL could name another host the traffic policy lets through, so neither
// request through the tunnel carries the session's token: the proxy authenticates the session from the tunnel and adds
// the token itself.
func TestTunneledRequestsCarryNoSessionToken(t *testing.T) {
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusOK, api.ListAgentVaultSessionServicesResponse{})
	tunnel, err := newAgentVaultSkillsTunnel(proxy.addr, "agv_tok", testProxyAPIURL, proxy.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok", tunnel: tunnel, includeBuiltin: true}
	if _, err := client.list(context.Background()); err != nil {
		t.Fatalf("skills: %v", err)
	}
	if _, err := client.services(context.Background()); err != nil {
		t.Fatalf("services: %v", err)
	}
	if proxy.requests.Load() != 2 || proxy.authorizations.Load() != nil || proxy.sessionToken.Load() != "agv_tok" {
		t.Fatalf("%d requests, Authorization %v, tunnel session %v", proxy.requests.Load(), proxy.authorizations.Load(), proxy.sessionToken.Load())
	}
}

// A proxy that names its Infisical only once it accepts the session, refusing it the first times it's asked.
func refusingThenNamingProxy(t *testing.T, refusals int32) (addr string, asked *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	asked = &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
					return
				}
				answer := agentvault.HeaderAPIURL + ": " + testProxyAPIURL
				if asked.Add(1) <= refusals {
					answer = agentvault.HeaderDecision + ": blocked"
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n"+answer+"\r\n\r\n")
			}()
		}
	}()
	return listener.Addr().String(), asked
}

// The proxy remembers a refusal for a few seconds, so a session this run just minted asks again until the proxy accepts
// it, and doesn't start the agent without discovery. A session from elsewhere asks once.
func TestAMintedSessionAsksAgainUntilTheProxyNamesItsInfisical(t *testing.T) {
	old := agentVaultSkillsUnauthorizedRetryDelays
	agentVaultSkillsUnauthorizedRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { agentVaultSkillsUnauthorizedRetryDelays = old })

	addr, asked := refusingThenNamingProxy(t, 2)
	if got, answered := askAgentVaultProxyAPIURL(context.Background(), addr, "agv_tok", true); got != testProxyAPIURL || !answered || asked.Load() != 3 {
		t.Fatalf("minted: named %q, answered %v, asked %d times", got, answered, asked.Load())
	}

	addr, asked = refusingThenNamingProxy(t, 2)
	if got, answered := askAgentVaultProxyAPIURL(context.Background(), addr, "agv_tok", false); got != "" || answered || asked.Load() != 1 {
		t.Fatalf("not minted: named %q, answered %v, asked %d times", got, answered, asked.Load())
	}
}

// A redirect's target could be outside TLS, where anyone between run and the proxy can write the answer, so run never
// follows one: the redirect itself is the answer, and a host's answer passed on contradicts the claim.
func TestARedirectIsNeverFollowedOutOfTheTunnel(t *testing.T) {
	proxy := newFakeTunnelProxy(t, "redirects", http.StatusOK, api.ListAgentVaultSessionSkillsResponse{})
	tunnel, err := newAgentVaultSkillsTunnel(proxy.addr, "agv_tok", testProxyAPIURL, proxy.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.CallListAgentVaultSessionSkillsThroughProxy(context.Background(), tunnel.httpClient, tunnel.tlsAPIURL, true,
		func(res *resty.Response) error { return tunnel.check(res, agentvault.DecisionSkills) })
	if !errors.Is(err, errAgentVaultProxyAnswerUnconfirmed) || proxy.requests.Load() != 1 || tunnel.confirmed || !tunnel.contradicted {
		t.Fatalf("err %v, %d requests, confirmed %v, contradicted %v", err, proxy.requests.Load(), tunnel.confirmed, tunnel.contradicted)
	}
}

// A refusal from the proxy after the CONNECT names no Infisical, so it neither confirms nor contradicts the claim, but
// its reason reaches the warning, such as a proxy whose token was revoked.
func TestARefusalAfterTheConnectKeepsItsReason(t *testing.T) {
	res := &resty.Response{
		Request: &resty.Request{Method: http.MethodGet, URL: testProxyAPIURL + "/v1/agent-vault/session/skills"},
		RawResponse: &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{
			agentvault.HeaderDecision: []string{"error"},
			"Content-Type":            []string{"application/json"},
		}},
	}
	res.SetBody([]byte(`{"error":"proxy_revoked","message":"this proxy's access has been revoked","hint":"rotate its token"}`))
	tunnel := &agentVaultSkillsTunnel{claimedAPIURL: testProxyAPIURL}

	err := tunnel.check(res, agentvault.DecisionSkills)
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.Name != "proxy_revoked" || tunnel.confirmed || tunnel.contradicted {
		t.Fatalf("err %v, confirmed %v, contradicted %v", err, tunnel.confirmed, tunnel.contradicted)
	}
	if reason := agentVaultSkillsFailureReason(err); reason != "this proxy's access has been revoked" {
		t.Fatalf("reason %q", reason)
	}
}
