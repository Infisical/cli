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
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
)

const testRunSkillID = "8f0e7c1a-3b9e-4c55-9d3e-2a1b7c6d5e4f"

func testProxySkill(name, content string) api.AgentVaultProxySkill {
	files := []api.AgentVaultSkillFile{{Path: "SKILL.md", Mode: "0644", ContentBase64: base64.StdEncoding.EncodeToString([]byte(content))}}
	return api.AgentVaultProxySkill{ID: testRunSkillID, Name: name, Version: 1, Sha256: agentvault.SkillFilesSha256(files), Files: files}
}

// A stand-in for `infisical agent-vault proxy`, answering the skills endpoint with status and skills.
func fakeSkillsProxy(t *testing.T, status int, skills ...api.AgentVaultProxySkill) *agentVaultSkillsClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentvault.SkillsPath {
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Proxy-Authorization"), "Basic ") {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.AgentVaultProxySkillsResponse{Skills: skills})
	}))
	t.Cleanup(srv.Close)
	return &agentVaultSkillsClient{proxyAddr: strings.TrimPrefix(srv.URL, "http://"), sessionToken: "agv_tok", httpClient: agentVaultSkillsHTTPClient}
}

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
	client := fakeSkillsProxy(t, http.StatusOK, testProxySkill("code-review", "---\nname: code-review\n---\n"))

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
	client := fakeSkillsProxy(t, http.StatusOK, testProxySkill("code-review", "x"))
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
	unreachable := &agentVaultSkillsClient{proxyAddr: "127.0.0.1:1", sessionToken: "agv_tok", httpClient: agentVaultSkillsHTTPClient}
	cases := map[string]*agentVaultSkillsClient{
		"old proxy":            fakeSkillsProxy(t, http.StatusNotFound),
		"Infisical too old":    fakeSkillsProxy(t, http.StatusNotImplemented),
		"session gone":         fakeSkillsProxy(t, http.StatusForbidden),
		"Infisical failing":    fakeSkillsProxy(t, http.StatusBadGateway),
		"no skills":            fakeSkillsProxy(t, http.StatusOK),
		"proxy is unreachable": unreachable,
	}
	for name, client := range cases {
		installAgentVaultRunSkills(context.Background(), "", client, os.Symlink)
		if exists(filepath.Join(home, ".agents")) {
			t.Fatalf("%s: a skills folder was created", name)
		}
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
	client := fakeSkillsProxy(t, http.StatusOK, testProxySkill("code-review", "x"))

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

func TestInterruptingAWaitForTheProxyRevokes(t *testing.T) {
	isolateSkillsHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	client := &agentVaultSkillsClient{proxyAddr: strings.TrimPrefix(srv.URL, "http://"), sessionToken: "agv_tok", httpClient: agentVaultSkillsHTTPClient}

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
	client := fakeSkillsProxy(t, http.StatusOK, testProxySkill("code-review", "x"))
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
