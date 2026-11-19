package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
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
		raw, _ := io.ReadAll(r.Body)
		var sent map[string]json.RawMessage
		_ = json.Unmarshal(raw, &sent)
		// What a version holds is its files, so that is what decides whether a publish changed anything.
		body := string(sent["files"])
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/agent-vault")
		switch {
		case r.Method == http.MethodGet && path == "/skills":
			f.calls = append(f.calls, "find "+r.URL.Query().Get("projectId")+" "+r.URL.Query().Get("name"))
			_ = json.NewEncoder(w).Encode(map[string]any{"skills": f.existing, "totalCount": len(f.existing)})
		case r.Method == http.MethodPost && path == "/skills":
			var projectID string
			_ = json.Unmarshal(sent["projectId"], &projectID)
			f.calls = append(f.calls, "create "+projectID)
			if f.createStatus != 0 {
				f.existing = f.existingAfterConflict
				w.WriteHeader(f.createStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": f.createStatus, "message": "taken", "error": "Conflict"})
				return
			}
			f.existing = []api.AgentVaultSkill{{ID: "new", Name: "code-review"}}
			f.lastBody, f.lastVersion = body, 1
			_ = json.NewEncoder(w).Encode(map[string]any{"skill": map[string]any{"id": "new", "name": "code-review"}, "version": map[string]any{"version": 1}})
		case r.Method == http.MethodPatch && strings.Count(path, "/") == 2:
			call := "update " + strings.Split(path, "/")[2]
			if _, ok := sent["projectId"]; ok {
				call += " with a projectId"
			}
			f.calls = append(f.calls, call)
			if f.lastBody == body {
				_ = json.NewEncoder(w).Encode(map[string]any{"version": map[string]any{"version": f.lastVersion}, "unchanged": true})
				return
			}
			f.lastBody, f.lastVersion = body, 4
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
		{"new name creates", &fakeSkillsAPI{}, "find p1 code-review,create p1", "code-review: created v1", false},
		{"known name publishes", &fakeSkillsAPI{existing: found}, "find p1 code-review,update sk1", "code-review: v4", false},
		{"lost create race publishes", &fakeSkillsAPI{createStatus: http.StatusConflict, existingAfterConflict: found},
			"find p1 code-review,create p1,find p1 code-review,update sk1", "code-review: v4", false},
		{"409 with nothing to find fails", &fakeSkillsAPI{createStatus: http.StatusConflict},
			"find p1 code-review,create p1,find p1 code-review", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.api
			client := newFakeSkillsAPI(t, f)
			out, err := pushAgentVaultSkill(client, "p1", "code-review", nil)
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
		out, err := pushAgentVaultSkill(client, "p1", name, files)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, out)
	}
	if got := strings.Join(outs, "|"); got != "code-review: created v1|code-review: unchanged (v1)" {
		t.Fatalf("outputs %s", got)
	}
	if got := strings.Join(f.calls, ","); got != "find p1 code-review,create p1,find p1 code-review,update new" {
		t.Fatalf("calls %s", got)
	}
}

// A stand-in for the skill read and delete routes. skills are what the list returns; files are each skill's
// latest files; versions holds the earlier versions, and a version missing from it answers 404.
type fakeSkillsReadAPI struct {
	mu       sync.Mutex
	skills   []api.AgentVaultSkill
	files    map[string][]api.AgentVaultSkillFile
	versions map[string][]api.AgentVaultSkillFile
	// goneAfterVersion deletes every skill when a version answers 404, as if one was deleted mid-pull.
	goneAfterVersion bool
	calls            []string
}

func newFakeSkillsReadAPI(t *testing.T, f *fakeSkillsReadAPI) *resty.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/agent-vault/skills")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		query := r.URL.Query()
		switch {
		case r.Method == http.MethodGet && path == "":
			matched := []api.AgentVaultSkill{}
			for _, skill := range f.skills {
				if name := query.Get("name"); name == "" || skill.Name == name {
					matched = append(matched, skill)
				}
			}
			offset, _ := strconv.Atoi(query.Get("offset"))
			limit, _ := strconv.Atoi(query.Get("limit"))
			if limit == 0 {
				limit = 20
			}
			page := matched[min(offset, len(matched)):min(offset+limit, len(matched))]
			if query.Get("name") != "" {
				f.calls = append(f.calls, "find "+query.Get("name"))
			} else {
				f.calls = append(f.calls, "list "+query.Get("offset"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"skills": page, "totalCount": len(matched)})
		case r.Method == http.MethodGet && len(parts) == 1:
			f.calls = append(f.calls, "get "+parts[0])
			for _, skill := range f.skills {
				if skill.ID == parts[0] {
					_ = json.NewEncoder(w).Encode(map[string]any{"skill": api.AgentVaultSkillWithFiles{AgentVaultSkill: skill, Files: f.files[skill.ID]}})
					return
				}
			}
			http.NotFound(w, r)
		case r.Method == http.MethodGet && len(parts) == 3 && parts[1] == "versions":
			f.calls = append(f.calls, "version "+parts[0]+" "+parts[2])
			files, ok := f.versions[parts[0]+"@"+parts[2]]
			if !ok {
				if f.goneAfterVersion {
					f.skills = nil
				}
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"statusCode": 404, "message": "Version " + parts[2] + " not found", "error": "NotFound"})
				return
			}
			version, _ := strconv.Atoi(parts[2])
			_ = json.NewEncoder(w).Encode(map[string]any{"version": map[string]any{"version": version, "files": files}})
		case r.Method == http.MethodDelete && len(parts) == 1:
			f.calls = append(f.calls, "delete "+parts[0])
			_ = json.NewEncoder(w).Encode(map[string]any{"skill": map[string]any{"id": parts[0]}})
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

var testSkillsProject = agentVaultProject{ID: testProjectID, Source: "--project-id", FromFlag: true}

func pullTestCmd() *cobra.Command {
	root := &cobra.Command{Use: "infisical"}
	av := &cobra.Command{Use: "agent-vault"}
	skills := &cobra.Command{Use: "skills"}
	pull := &cobra.Command{Use: "pull", Run: func(*cobra.Command, []string) {}}
	pull.Flags().Bool("force", false, "")
	root.AddCommand(av)
	av.AddCommand(skills)
	skills.AddCommand(pull)
	return pull
}

func skillFileOf(path, mode, content string) api.AgentVaultSkillFile {
	return api.AgentVaultSkillFile{Path: path, Mode: mode, ContentBase64: base64.StdEncoding.EncodeToString([]byte(content))}
}

func codeReviewSkillAPI() *fakeSkillsReadAPI {
	return &fakeSkillsReadAPI{
		skills: []api.AgentVaultSkill{{ID: "sk1", Name: "code-review", LatestVersion: 4,
			AccessBundles: []api.AgentVaultSkillAccessBundle{{ID: "b1", Name: "dev"}, {ID: "b2", Name: "prod"}}}},
		files: map[string][]api.AgentVaultSkillFile{"sk1": {
			skillFileOf("SKILL.md", "0644", "---\nname: code-review\n---\nv4\n"),
			skillFileOf("scripts/lint.sh", "0755", "#!/bin/sh\n"),
		}},
		versions: map[string][]api.AgentVaultSkillFile{
			"sk1@2": {skillFileOf("SKILL.md", "0644", "---\nname: code-review\n---\nv2\n")},
			"sk1@4": {skillFileOf("SKILL.md", "0644", "---\nname: code-review\n---\nv4 by number\n")},
		},
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestListAgentVaultSkillsReadsEveryPage(t *testing.T) {
	f := &fakeSkillsReadAPI{}
	for i := range 150 {
		f.skills = append(f.skills, api.AgentVaultSkill{ID: strconv.Itoa(i), Name: "skill-" + strconv.Itoa(i)})
	}
	skills, err := listAgentVaultSkills(newFakeSkillsReadAPI(t, f), testSkillsProject)
	if err != nil {
		t.Fatal(err)
	}
	if len(skills) != 150 {
		t.Fatalf("got %d skills", len(skills))
	}
	if got := strings.Join(f.calls, ","); got != "list 0,list 100" {
		t.Fatalf("calls %s", got)
	}
}

func TestListAgentVaultSkillsOfAnEmptyProjectIsAnEmptyList(t *testing.T) {
	skills, err := listAgentVaultSkills(newFakeSkillsReadAPI(t, &fakeSkillsReadAPI{}), testSkillsProject)
	if err != nil || skills == nil || len(skills) != 0 {
		t.Fatalf("skills %#v, err %v", skills, err)
	}
}

func TestPullAgentVaultSkillWritesTheLatestVersion(t *testing.T) {
	f := codeReviewSkillAPI()
	folder := filepath.Join(t.TempDir(), "nested", "code-review")

	out, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, f), testSkillsProject, "code-review", folder, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if out != "code-review: v4 -> "+folder {
		t.Fatalf("out %q", out)
	}
	if got := readTestFile(t, filepath.Join(folder, "SKILL.md")); !strings.HasSuffix(got, "v4\n") {
		t.Fatalf("SKILL.md %q", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(folder, "scripts", "lint.sh"))
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("lint.sh %v %v", info, err)
		}
	}
	if got := strings.Join(f.calls, ","); got != "find code-review,get sk1" {
		t.Fatalf("calls %s", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(folder))
	if len(entries) != 1 {
		t.Fatalf("the pull left %d entries beside the folder", len(entries))
	}
}

func TestPulledSkillPushesBackUnchanged(t *testing.T) {
	f := codeReviewSkillAPI()
	folder := filepath.Join(t.TempDir(), "code-review")
	if _, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, f), testSkillsProject, "code-review", folder, 0, false); err != nil {
		t.Fatal(err)
	}
	files, name, err := readAgentVaultSkillFolder(folder)
	if err != nil {
		t.Fatal(err)
	}
	if name != "code-review" || agentvault.SkillFilesSha256(files) != agentvault.SkillFilesSha256(f.files["sk1"]) {
		t.Fatalf("the pulled folder reads back as %q %+v", name, files)
	}
}

func TestPullAgentVaultSkillVersions(t *testing.T) {
	cases := []struct {
		name      string
		version   int
		wantCalls string
		wantErr   string
		wantBody  string
	}{
		{"an earlier version", 2, "find code-review,version sk1 2", "", "v2\n"},
		{"the latest by number", 4, "find code-review,version sk1 4", "", "v4 by number\n"},
		{"past the latest", 9, "find code-review", "has no version 9. Its latest version is 4", ""},
		{"one the server won't give", 3, "find code-review,version sk1 3,find code-review", "Only an Admin of the project can pull a version of \"code-review\" other than the latest (4)", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := codeReviewSkillAPI()
			folder := filepath.Join(t.TempDir(), "code-review")
			_, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, f), testSkillsProject, "code-review", folder, tc.version, false)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v", err)
				}
				if _, statErr := os.Stat(folder); !os.IsNotExist(statErr) {
					t.Fatal("a failed pull created the folder")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if got := readTestFile(t, filepath.Join(folder, "SKILL.md")); !strings.HasSuffix(got, tc.wantBody) {
				t.Fatalf("SKILL.md %q", got)
			}
			if got := strings.Join(f.calls, ","); got != tc.wantCalls {
				t.Fatalf("calls %s, want %s", got, tc.wantCalls)
			}
		})
	}
}

func TestPullAgentVaultSkillThatDoesNotExist(t *testing.T) {
	_, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, codeReviewSkillAPI()), testSkillsProject, "nope", filepath.Join(t.TempDir(), "nope"), 0, false)
	var cliErr *util.CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != errCodeSkillNotFound || !strings.Contains(cliErr.Message, `No skill named "nope"`) ||
		len(cliErr.Next) != 1 || cliErr.Next[0].Command != "infisical agent-vault skills get --project-id "+testProjectID {
		t.Fatalf("err %#v", err)
	}
}

func TestPullAgentVaultSkillIntoAnExistingFolder(t *testing.T) {
	folder := filepath.Join(t.TempDir(), "code-review")
	for _, rel := range []string{"SKILL.md", "notes.md", ".git/config"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(folder, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folder, rel), []byte("local"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	err := checkAgentVaultSkillPullTarget(pullTestCmd(), nil, folder, false)
	if err == nil || !strings.Contains(err.Error(), "Pass --force to replace it") {
		t.Fatalf("err %v", err)
	}
	if err := checkAgentVaultSkillPullTarget(pullTestCmd(), nil, folder, true); err != nil {
		t.Fatal(err)
	}

	if _, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, codeReviewSkillAPI()), testSkillsProject, "code-review", folder, 0, true); err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, filepath.Join(folder, "SKILL.md")); !strings.HasSuffix(got, "v4\n") {
		t.Fatalf("SKILL.md %q", got)
	}
	for _, rel := range []string{"notes.md", ".git"} {
		if _, err := os.Stat(filepath.Join(folder, rel)); !os.IsNotExist(err) {
			t.Fatalf("%s survived --force", rel)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(folder))
	if len(entries) != 1 {
		t.Fatalf("the pull left %d entries beside the folder", len(entries))
	}
}

func TestPullAgentVaultSkillThatFailsLeavesTheFolderAlone(t *testing.T) {
	f := codeReviewSkillAPI()
	f.files["sk1"] = append(f.files["sk1"], skillFileOf("../escape.md", "0644", "x"))
	parent := t.TempDir()
	folder := filepath.Join(parent, "code-review")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "SKILL.md"), []byte("local"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, f), testSkillsProject, "code-review", folder, 0, true)
	if err == nil || !strings.Contains(err.Error(), "outside its folder") {
		t.Fatalf("err %v", err)
	}
	if got := readTestFile(t, filepath.Join(folder, "SKILL.md")); got != "local" {
		t.Fatalf("the folder was changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(parent, "escape.md")); !os.IsNotExist(err) {
		t.Fatal("a file was written outside the folder")
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 {
		t.Fatalf("the failed pull left %d entries beside the folder", len(entries))
	}
}

func TestCheckAgentVaultSkillPullTargetRefusesWhatCannotBeReplaced(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkAgentVaultSkillPullTarget(pullTestCmd(), nil, file, true); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Fatalf("a file: %v", err)
	}

	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(t.TempDir(), link); err != nil {
			t.Fatal(err)
		}
		if err := checkAgentVaultSkillPullTarget(pullTestCmd(), nil, link, true); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("a symlink: %v", err)
		}
	}

	holder := filepath.Join(dir, "holder")
	inside := filepath.Join(holder, "inside")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(inside)
	for _, target := range []string{".", holder} {
		if err := checkAgentVaultSkillPullTarget(pullTestCmd(), nil, target, true); err == nil || !strings.Contains(err.Error(), "is, or holds, the current folder") {
			t.Fatalf("%s: %v", target, err)
		}
	}
	if err := checkAgentVaultSkillPullTarget(pullTestCmd(), nil, filepath.Join(dir, "missing"), false); err != nil {
		t.Fatalf("a folder that doesn't exist yet: %v", err)
	}
}

func TestAgentVaultSkillDeleteAsksWithTheProjectPinned(t *testing.T) {
	fakeTerminal(t, false, "", nil)
	root := &cobra.Command{Use: "infisical"}
	root.PersistentFlags().String("domain", "", "")
	av := &cobra.Command{Use: "agent-vault"}
	skills := &cobra.Command{Use: "skills"}
	del := &cobra.Command{Use: "delete <name>", Args: cobra.ExactArgs(1), Run: func(*cobra.Command, []string) {}}
	del.Flags().String("project-id", "", "")
	addConfirmFlags(del)
	root.AddCommand(av)
	av.AddCommand(skills)
	skills.AddCommand(del)

	skill := api.AgentVaultSkill{ID: "sk1", Name: "code-review", AccessBundles: []api.AgentVaultSkillAccessBundle{{ID: "b1"}, {ID: "b2"}}}
	action := agentVaultSkillDeleteAction(skill, testProjectID)
	if action.Description != "skill code-review and removes it from 2 access bundles" {
		t.Fatalf("description %q", action.Description)
	}

	for _, args := range [][]string{{"code-review"}, {"code-review", "--project-id", testProjectID}} {
		cmd, rest, err := root.Find(append([]string{"agent-vault", "skills", "delete"}, args...))
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.ParseFlags(rest); err != nil {
			t.Fatal(err)
		}
		err = confirmDestructive(cmd, cmd.Flags().Args(), action)
		var cliErr *util.CLIError
		if !errors.As(err, &cliErr) || cliErr.Code != errCodeConfirmationRequired || len(cliErr.Next) != 1 {
			t.Fatalf("err %v", err)
		}
		want := "infisical agent-vault skills delete code-review --project-id " + testProjectID + " --yes"
		if got := cliErr.Next[0].Command; got != want {
			t.Fatalf("rerun\n got %s\nwant %s", got, want)
		}
	}

	if err := del.Flags().Set("yes", "true"); err != nil {
		t.Fatal(err)
	}
	if err := confirmDestructive(del, []string{"code-review"}, action); err != nil {
		t.Fatalf("--yes still asked: %v", err)
	}
}

func TestPullAgentVaultSkillIntoAnExistingFolderSuggestsForce(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("code-review", 0o755); err != nil {
		t.Fatal(err)
	}
	err := checkAgentVaultSkillPullTarget(pullTestCmd(), []string{"code-review"}, "code-review", false)
	var cliErr *util.CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != errCodeInvalidArgument || len(cliErr.Next) != 1 {
		t.Fatalf("err %#v", err)
	}
	if got, want := cliErr.Next[0].Command, "infisical agent-vault skills pull code-review --force"; got != want {
		t.Fatalf("suggestion\n got %s\nwant %s", got, want)
	}
}

func TestGetAgentVaultSkillListsItsFilesWithoutContents(t *testing.T) {
	f := codeReviewSkillAPI()
	detail, err := getAgentVaultSkill(newFakeSkillsReadAPI(t, f), testSkillsProject, "code-review")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Name != "code-review" || detail.LatestVersion != 4 || len(detail.AccessBundles) != 2 {
		t.Fatalf("detail %+v", detail)
	}
	out, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "contentBase64") || !strings.Contains(string(out), `{"path":"scripts/lint.sh","mode":"0755"}`) {
		t.Fatalf("json %s", out)
	}
	if got := strings.Join(f.calls, ","); got != "find code-review,get sk1" {
		t.Fatalf("calls %s", got)
	}
}

func TestDeleteAgentVaultSkillNeedsATypedProject(t *testing.T) {
	t.Setenv(agentVaultProjectIDEnv, testProjectID)
	err := errAgentVaultSkillDeleteProjectRequired()
	if err.Code != errCodeProjectRequired || !strings.Contains(err.Message, "needs --project-id") {
		t.Fatalf("err %#v", err)
	}
	if agentVaultSkillsDeleteCmd.Flags().Changed("project-id") {
		t.Fatal("the delete command starts with --project-id set")
	}
}

func TestPullAgentVaultSkillSkipsHiddenFiles(t *testing.T) {
	f := codeReviewSkillAPI()
	f.files["sk1"] = append(f.files["sk1"],
		skillFileOf(".git/config", "0644", "[core]\n\tfsmonitor = touch pwned\n"),
		skillFileOf("scripts/.env", "0644", "x"))
	folder := filepath.Join(t.TempDir(), "code-review")
	if _, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, f), testSkillsProject, "code-review", folder, 0, false); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{".git", "scripts/.env"} {
		if _, err := os.Lstat(filepath.Join(folder, rel)); !os.IsNotExist(err) {
			t.Fatalf("%s was written", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(folder, "scripts", "lint.sh")); err != nil {
		t.Fatal(err)
	}
}

func TestPullAgentVaultSkillErrorsDoNotRepeatTheFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only folders work differently on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can write to read-only folders")
	}
	parent := filepath.Join(t.TempDir(), "ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	if err := os.Mkdir(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	_, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, codeReviewSkillAPI()), testSkillsProject, "code-review", filepath.Join(parent, "x"), 0, false)
	if err == nil || strings.Contains(err.Error(), "ghp_") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err %v", err)
	}
}

func TestPullAgentVaultSkillVersionOfASkillDeletedMidPull(t *testing.T) {
	f := codeReviewSkillAPI()
	f.goneAfterVersion = true
	_, err := pullAgentVaultSkill(newFakeSkillsReadAPI(t, f), testSkillsProject, "code-review", filepath.Join(t.TempDir(), "x"), 3, false)
	var cliErr *util.CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != errCodeSkillNotFound {
		t.Fatalf("err %#v", err)
	}
	if got := strings.Join(f.calls, ","); got != "find code-review,version sk1 3,find code-review" {
		t.Fatalf("calls %s", got)
	}
}

func TestCheckAgentVaultSkillPullTargetSeesASymlinkWithATrailingSlash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on Windows")
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "mylink")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if err := checkAgentVaultSkillPullTarget(pullTestCmd(), nil, link+"/", true); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("err %v", err)
	}
	if err := replaceAgentVaultSkillFolder(link+"/", codeReviewSkillAPI().files["sk1"], true); err == nil {
		t.Fatal("the replace wrote over a symlink")
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced: %v %v", info, err)
	}
}

func TestPullIntoTheCurrentFolderGetsTheRealReasonWithoutForce(t *testing.T) {
	t.Chdir(t.TempDir())
	err := checkAgentVaultSkillPullTarget(pullTestCmd(), []string{"code-review", "."}, ".", false)
	if err == nil || !strings.Contains(err.Error(), "is, or holds, the current folder") {
		t.Fatalf("err %v", err)
	}
}
