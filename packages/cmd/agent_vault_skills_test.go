package cmd

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

func TestReadAgentVaultSkillFolder(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("SKILL.md", "---\nname: code-review\n---\n", 0o644)
	write("scripts/run.sh", "#!/bin/sh", 0o755)
	write(".DS_Store", "x", 0o644)
	write(".git/config", "x", 0o644)
	write("scripts/.env", "x", 0o644)

	files, name, err := readAgentVaultSkillFolder(dir)
	if err != nil {
		t.Fatal(err)
	}
	if name != "code-review" {
		t.Fatalf("name %q", name)
	}
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = f.Mode
	}
	if len(files) != 2 || byPath["SKILL.md"] != "0644" {
		t.Fatalf("files %+v", files)
	}
	if runtime.GOOS != "windows" && byPath["scripts/run.sh"] != "0755" {
		t.Fatalf("the script was sent as %q", byPath["scripts/run.sh"])
	}
	for _, f := range files {
		if f.Path == "scripts/run.sh" {
			content, _ := base64.StdEncoding.DecodeString(f.ContentBase64)
			if string(content) != "#!/bin/sh" {
				t.Fatalf("content %q", content)
			}
		}
	}

	if _, _, err := readAgentVaultSkillFolder(filepath.Join(dir, "scripts")); err == nil {
		t.Fatal("a folder without SKILL.md was accepted")
	}
}

func TestReadAgentVaultSkillFolderThroughASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	real := filepath.Join(t.TempDir(), "code-review")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "SKILL.md"), []byte("---\nname: code-review\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	files, name, err := readAgentVaultSkillFolder(link)
	if err != nil {
		t.Fatal(err)
	}
	if name != "code-review" || len(files) != 1 || files[0].Path != "SKILL.md" {
		t.Fatalf("name %q, files %+v", name, files)
	}

	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(real, "notes.md")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readAgentVaultSkillFolder(link); err == nil || !strings.Contains(err.Error(), "notes.md is not a regular file") {
		t.Fatalf("a symlink inside the folder was not refused: %v", err)
	}
}

// A stand-in for Infisical's skill routes. existing is what the name lookup finds; existingAfterConflict is
// what it finds once a create has answered 409.
type fakeSkillsAPI struct {
	mu                    sync.Mutex
	existing              []api.AgentVaultSkill
	existingAfterConflict []api.AgentVaultSkill
	createStatus          int
	calls                 []string
	lastBody              string
	lastVersion           int
}

func newFakeSkillsAPI(t *testing.T, f *fakeSkillsAPI) *resty.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/agent-vault")
		switch {
		case r.Method == http.MethodGet && path == "/skills":
			f.calls = append(f.calls, "find "+r.URL.Query().Get("name"))
			_ = json.NewEncoder(w).Encode(map[string]any{"skills": f.existing, "totalCount": len(f.existing)})
		case r.Method == http.MethodPost && path == "/skills":
			f.calls = append(f.calls, "create")
			if f.createStatus != 0 {
				f.existing = f.existingAfterConflict
				w.WriteHeader(f.createStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": f.createStatus, "message": "taken", "error": "Conflict"})
				return
			}
			f.existing = []api.AgentVaultSkill{{ID: "new", Name: "code-review"}}
			f.lastBody, f.lastVersion = string(body), 1
			_ = json.NewEncoder(w).Encode(map[string]any{"skill": map[string]any{"id": "new", "name": "code-review"}, "version": map[string]any{"version": 1}})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/versions"):
			f.calls = append(f.calls, "publish "+strings.Split(path, "/")[2])
			if f.lastBody == string(body) {
				_ = json.NewEncoder(w).Encode(map[string]any{"version": map[string]any{"version": f.lastVersion}, "unchanged": true})
				return
			}
			f.lastBody, f.lastVersion = string(body), 4
			_ = json.NewEncoder(w).Encode(map[string]any{"version": map[string]any{"version": 4}, "unchanged": false})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })
	return resty.New()
}

func TestPushAgentVaultSkill(t *testing.T) {
	found := []api.AgentVaultSkill{{ID: "sk1", Name: "code-review"}}
	cases := []struct {
		name      string
		api       *fakeSkillsAPI
		wantCalls string
		wantOut   string
		wantErr   bool
	}{
		{"new name creates", &fakeSkillsAPI{}, "find code-review,create", "code-review: created v1", false},
		{"known name publishes", &fakeSkillsAPI{existing: found}, "find code-review,publish sk1", "code-review: v4", false},
		{"lost create race publishes", &fakeSkillsAPI{createStatus: http.StatusConflict, existingAfterConflict: found},
			"find code-review,create,find code-review,publish sk1", "code-review: v4", false},
		{"409 with nothing to find fails", &fakeSkillsAPI{createStatus: http.StatusConflict},
			"find code-review,create,find code-review", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.api
			client := newFakeSkillsAPI(t, f)
			out, err := pushAgentVaultSkill(client, "code-review", api.AgentVaultSkillFilesRequest{})
			if (err != nil) != tc.wantErr || out != tc.wantOut {
				t.Fatalf("out %q, err %v", out, err)
			}
			if got := strings.Join(f.calls, ","); got != tc.wantCalls {
				t.Fatalf("calls %s, want %s", got, tc.wantCalls)
			}
		})
	}
}

func TestPushAgentVaultSkillTwiceIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: code-review\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeSkillsAPI{}
	client := newFakeSkillsAPI(t, f)

	var outs []string
	for range 2 {
		files, name, err := readAgentVaultSkillFolder(dir)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pushAgentVaultSkill(client, name, api.AgentVaultSkillFilesRequest{Files: files})
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, out)
	}
	if got := strings.Join(outs, "|"); got != "code-review: created v1|code-review: unchanged (v1)" {
		t.Fatalf("outputs %s", got)
	}
	if got := strings.Join(f.calls, ","); got != "find code-review,create,find code-review,publish new" {
		t.Fatalf("calls %s", got)
	}
}
