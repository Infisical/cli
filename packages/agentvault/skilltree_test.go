package agentvault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

func TestMain(m *testing.M) {
	locks, err := os.MkdirTemp("", "agentvault-skill-locks")
	if err != nil {
		panic(err)
	}
	skillsLockDir = func() (string, error) { return locks, nil }
	code := m.Run()
	_ = os.RemoveAll(locks)
	os.Exit(code)
}

// markAsInstalled makes folder look like one an earlier run wrote.
func markAsInstalled(t *testing.T, folder string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(folder, SkillMarkerFile), []byte(`{"skillId":"old","sha256":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func skillFile(path, mode, content string) api.AgentVaultSkillFile {
	return api.AgentVaultSkillFile{Path: path, Mode: mode, ContentBase64: base64.StdEncoding.EncodeToString([]byte(content))}
}

func sessionSkill(name string, files ...api.AgentVaultSkillFile) api.AgentVaultSessionSkill {
	return api.AgentVaultSessionSkill{Name: name, Version: 1, Sha256: SkillFilesSha256(files), Files: files}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// isolateHome points the home folder and the agents' folder variables at a fresh temporary folder.
func isolateHome(t *testing.T) string {
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

func install(t *testing.T, opts InstallOptions, skills ...api.AgentVaultSessionSkill) InstallResult {
	t.Helper()
	result, err := InstallSkills(t.Context(), skills, opts)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func linkedAgents(result InstallResult) []string {
	var agents []string
	for _, linked := range result.Linked {
		agents = append(agents, linked.Agent)
	}
	return agents
}

func assertLinked(t *testing.T, link, canonical string) {
	t.Helper()
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("%s is not a link: %v", link, err)
	}
	if target != canonical {
		t.Fatalf("%s points at %s, want %s", link, target, canonical)
	}
}

func TestInstallSkillsWritesToTheHomeFolder(t *testing.T) {
	home := isolateHome(t)
	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "v1")))

	dir := filepath.Join(home, ".agents", "skills")
	if result.Dir != dir || result.Installed != 1 || len(result.Failed) != 0 || len(result.Linked) != 0 {
		t.Fatalf("result %+v", result)
	}
	if got := readFile(t, filepath.Join(dir, "code-review", "SKILL.md")); got != "v1" {
		t.Fatalf("SKILL.md %q", got)
	}
	if exists(filepath.Join(home, ".claude")) || exists(filepath.Join(home, ".hermes")) {
		t.Fatal("an agent folder was created for an agent that is not installed")
	}
}

func TestInstallSkillsReplacesAFolderItInstalled(t *testing.T) {
	home := isolateHome(t)
	dest := filepath.Join(home, ".agents", "skills", "code-review")
	mkdir(t, filepath.Join(dest, "scripts"))
	if err := os.WriteFile(filepath.Join(dest, "scripts", "stale.sh"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	markAsInstalled(t, dest)

	install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "v2")))
	if got := readFile(t, filepath.Join(dest, "SKILL.md")); got != "v2" {
		t.Fatalf("SKILL.md %q", got)
	}
	if exists(filepath.Join(dest, "scripts")) {
		t.Fatal("files from the replaced folder were kept")
	}
}

func TestInstallSkillsLinksOnlyForAgentsThatAreInstalled(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude"))
	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))

	canonical := filepath.Join(home, ".agents", "skills", "code-review")
	assertLinked(t, filepath.Join(home, ".claude", "skills", "code-review"), canonical)
	if exists(filepath.Join(home, ".hermes")) {
		t.Fatal("a folder was created for Hermes, which is not installed")
	}
	if !reflect.DeepEqual(linkedAgents(result), []string{ClaudeCodeAgent}) {
		t.Fatalf("linked %v", result.Linked)
	}

	mkdir(t, filepath.Join(home, ".hermes"))
	result = install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))
	assertLinked(t, filepath.Join(home, ".claude", "skills", "code-review"), canonical)
	assertLinked(t, filepath.Join(home, ".hermes", "skills", "code-review"), canonical)
	if !reflect.DeepEqual(linkedAgents(result), []string{ClaudeCodeAgent, HermesAgent}) {
		t.Fatalf("linked %v", result.Linked)
	}
}

func TestInstallSkillsFollowsTheAgentFolderVariables(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude"))
	mkdir(t, filepath.Join(home, ".hermes"))
	claude, hermes := t.TempDir(), t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", claude)
	t.Setenv("HERMES_HOME", hermes)

	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))
	canonical := filepath.Join(home, ".agents", "skills", "code-review")
	assertLinked(t, filepath.Join(claude, "skills", "code-review"), canonical)
	assertLinked(t, filepath.Join(hermes, "skills", "code-review"), canonical)
	if exists(filepath.Join(home, ".claude", "skills")) || exists(filepath.Join(home, ".hermes", "skills")) {
		t.Fatal("the default agent folders were used although the variables point elsewhere")
	}
	if !reflect.DeepEqual(linkedAgents(result), []string{ClaudeCodeAgent, HermesAgent}) {
		t.Fatalf("linked %v", result.Linked)
	}
}

func TestInstallSkillsReplacesAnEarlierCopyOfTheSkillInTheAgentFolder(t *testing.T) {
	home := isolateHome(t)
	copied := filepath.Join(home, ".claude", "skills", "code-review")
	mkdir(t, copied)
	if err := os.WriteFile(filepath.Join(copied, "SKILL.md"), []byte("---\nname: code-review\n---\nold"), 0o644); err != nil {
		t.Fatal(err)
	}
	markAsInstalled(t, copied)
	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "ours")))
	assertLinked(t, copied, filepath.Join(home, ".agents", "skills", "code-review"))
	if len(result.LinkFailed) != 0 {
		t.Fatalf("result %+v", result)
	}
}

func TestInstallSkillsReplacesALinkIntoTheInstallFolder(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude", "skills"))
	link := filepath.Join(home, ".claude", "skills", "code-review")
	if err := os.Symlink(filepath.Join(home, ".agents", "skills", "old-name"), link); err != nil {
		t.Fatal(err)
	}
	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "ours")))
	assertLinked(t, link, filepath.Join(home, ".agents", "skills", "code-review"))
	if len(result.LinkFailed) != 0 {
		t.Fatalf("result %+v", result)
	}
}

func TestInstallSkillsKeepsTheUsersLinkInTheAgentFolder(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude", "skills"))
	link := filepath.Join(home, ".claude", "skills", "code-review")
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "ours")))
	assertLinked(t, link, elsewhere)
	want := []string{"code-review for Claude Code (a link named code-review already exists and wasn't installed by Infisical)"}
	if result.Installed != 1 || !reflect.DeepEqual(result.LinkFailed, want) {
		t.Fatalf("result %+v", result)
	}
}

func TestInstallSkillsKeepsTheUsersFolderInTheAgentFolder(t *testing.T) {
	for name, skillMd := range map[string]string{
		"no SKILL.md":          "",
		"no header":            "mine",
		"another skill's name": "---\nname: my-review\n---\n",
		"the same name":        "---\nname: code-review\n---\nmine",
	} {
		t.Run(name, func(t *testing.T) {
			home := isolateHome(t)
			userSkill := filepath.Join(home, ".claude", "skills", "code-review")
			mkdir(t, userSkill)
			if skillMd != "" {
				if err := os.WriteFile(filepath.Join(userSkill, "SKILL.md"), []byte(skillMd), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "ours")))
			info, err := os.Lstat(userSkill)
			if err != nil || !info.IsDir() {
				t.Fatalf("the user's folder was replaced: %v", err)
			}
			if skillMd != "" && readFile(t, filepath.Join(userSkill, "SKILL.md")) != skillMd {
				t.Fatal("the user's SKILL.md was changed")
			}
			want := []string{"code-review for Claude Code (a folder named code-review already exists and wasn't installed by Infisical)"}
			if result.Installed != 1 || !reflect.DeepEqual(result.LinkFailed, want) || len(result.Linked) != 0 {
				t.Fatalf("result %+v", result)
			}
		})
	}
}

func TestInstallSkillsNamesACaseVariantFolderAsItIsOnDisk(t *testing.T) {
	home := isolateHome(t)
	skillsDir := filepath.Join(home, ".claude", "skills")
	mkdir(t, filepath.Join(skillsDir, "Code-Review"))
	if _, err := os.Lstat(filepath.Join(skillsDir, "code-review")); err != nil {
		t.Skip("this file system tells names apart by case")
	}
	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "ours")))
	if info, err := os.Lstat(filepath.Join(skillsDir, "Code-Review")); err != nil || !info.IsDir() {
		t.Fatalf("the user's folder was replaced: %v", err)
	}
	want := []string{"code-review for Claude Code (a folder named Code-Review already exists and wasn't installed by Infisical)"}
	if !reflect.DeepEqual(result.LinkFailed, want) {
		t.Fatalf("link failures %q", result.LinkFailed)
	}
}

func TestInstallSkillsLinksForClaudeCodeWhenItIsTheAgent(t *testing.T) {
	home := isolateHome(t)
	result := install(t, InstallOptions{ForceClaude: true}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))
	assertLinked(t, filepath.Join(home, ".claude", "skills", "code-review"), filepath.Join(home, ".agents", "skills", "code-review"))
	want := []LinkedAgent{{Agent: ClaudeCodeAgent, Dir: filepath.Join(home, ".claude", "skills")}}
	if !reflect.DeepEqual(result.Linked, want) {
		t.Fatalf("linked %+v", result.Linked)
	}
	if exists(filepath.Join(home, ".hermes")) {
		t.Fatal("a folder was created for Hermes, which is not installed")
	}
}

func TestInstallSkillsDoesNotLinkASkillsFolderThatIsTheInstallFolder(t *testing.T) {
	home := isolateHome(t)
	canonical := filepath.Join(home, ".agents", "skills")
	mkdir(t, canonical)
	mkdir(t, filepath.Join(home, ".claude"))
	if err := os.Symlink(canonical, filepath.Join(home, ".claude", "skills")); err != nil {
		t.Fatal(err)
	}

	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))
	info, err := os.Lstat(filepath.Join(canonical, "code-review"))
	if err != nil || !info.IsDir() {
		t.Fatalf("the installed skill was replaced by a link to itself: %v", err)
	}
	if got := readFile(t, filepath.Join(canonical, "code-review", "SKILL.md")); got != "x" {
		t.Fatalf("SKILL.md %q", got)
	}
	if len(result.LinkFailed) != 0 || len(result.Linked) != 0 {
		t.Fatalf("result %+v", result)
	}
}

func TestInstallSkillsDoesNotLinkARelativeAgentFolderIntoTheInstallFolder(t *testing.T) {
	home := isolateHome(t)
	canonical := filepath.Join(home, ".agents", "skills")
	mkdir(t, canonical)
	mkdir(t, filepath.Join(home, "claude"))
	if err := os.Symlink(filepath.Join("..", ".agents", "skills"), filepath.Join(home, "claude", "skills")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(home)
	t.Setenv("CLAUDE_CONFIG_DIR", "claude")

	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))
	info, err := os.Lstat(filepath.Join(canonical, "code-review"))
	if err != nil || !info.IsDir() {
		t.Fatalf("the installed skill was replaced by a link to itself: %v", err)
	}
	if got := readFile(t, filepath.Join(canonical, "code-review", "SKILL.md")); got != "x" {
		t.Fatalf("SKILL.md %q", got)
	}
	if len(result.LinkFailed) != 0 || len(result.Linked) != 0 {
		t.Fatalf("result %+v", result)
	}
}

func TestInstallSkillsNamesARelativeAgentFolderInFull(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, "claude"))
	t.Chdir(home)
	t.Setenv("CLAUDE_CONFIG_DIR", "claude")

	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))
	skillsDir := filepath.Join(home, "claude", "skills")
	assertLinked(t, filepath.Join(skillsDir, "code-review"), filepath.Join(home, ".agents", "skills", "code-review"))
	if want := []LinkedAgent{{Agent: ClaudeCodeAgent, Dir: skillsDir}}; !reflect.DeepEqual(result.Linked, want) {
		t.Fatalf("linked %+v", result.Linked)
	}
}

func TestInstallSkillsCopiesWhereLinksAreRefused(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude"))
	refuse := func(string, string) error { return errors.New("links are not allowed") }

	result := install(t, InstallOptions{Symlink: refuse}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))
	dest := filepath.Join(home, ".claude", "skills", "code-review")
	info, err := os.Lstat(dest)
	if err != nil || !info.IsDir() {
		t.Fatalf("no copy was written: %v", err)
	}
	if got := readFile(t, filepath.Join(dest, "SKILL.md")); got != "x" {
		t.Fatalf("SKILL.md %q", got)
	}
	if len(result.LinkFailed) != 0 || !reflect.DeepEqual(linkedAgents(result), []string{ClaudeCodeAgent}) {
		t.Fatalf("result %+v", result)
	}
}

func TestInstallSkillsIntoAChosenFolderMakesNoLinks(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude"))
	mkdir(t, filepath.Join(home, ".hermes"))
	dir := filepath.Join(t.TempDir(), "skills")

	result := install(t, InstallOptions{Dir: dir}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")))
	if result.Dir != dir || result.Installed != 1 || len(result.Linked) != 0 {
		t.Fatalf("result %+v", result)
	}
	if got := readFile(t, filepath.Join(dir, "code-review", "SKILL.md")); got != "x" {
		t.Fatalf("SKILL.md %q", got)
	}
	for _, path := range []string{
		filepath.Join(home, ".agents"),
		filepath.Join(home, ".claude", "skills"),
		filepath.Join(home, ".hermes", "skills"),
	} {
		if exists(path) {
			t.Fatalf("%s was written although a folder was chosen", path)
		}
	}
}

func TestInstallSkillsSkipsASkillThatFailsItsChecksum(t *testing.T) {
	dir := t.TempDir()
	bad := sessionSkill("tampered", skillFile("SKILL.md", "0644", "x"))
	bad.Files[0] = skillFile("SKILL.md", "0644", "changed")
	result := install(t, InstallOptions{Dir: dir}, bad, sessionSkill("code-review", skillFile("SKILL.md", "0644", "y")))
	if result.Installed != 1 || !reflect.DeepEqual(result.Failed, []string{"tampered (its files do not match their checksum)"}) {
		t.Fatalf("result %+v", result)
	}
	if exists(filepath.Join(dir, "tampered")) {
		t.Fatal("a skill that failed its checksum was written")
	}
}

func TestInstallSkillsNamesWhatTheDeadlineLeft(t *testing.T) {
	dir := t.TempDir()
	skills := []api.AgentVaultSessionSkill{
		sessionSkill("code-review", skillFile("SKILL.md", "0644", "x")),
		sessionSkill("deploy", skillFile("SKILL.md", "0644", "y")),
	}

	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	result, err := InstallSkills(expired, skills, InstallOptions{Dir: dir})
	if err != nil || result.Installed != 0 || !reflect.DeepEqual(result.Failed, []string{"code-review (timed out)", "deploy (timed out)"}) {
		t.Fatalf("result %+v, err %v", result, err)
	}

	interrupted, interrupt := context.WithCancel(t.Context())
	interrupt()
	result, err = InstallSkills(interrupted, skills, InstallOptions{Dir: dir})
	if err != nil || result.Installed != 0 || len(result.Failed) != 0 {
		t.Fatalf("an interrupt reported skills as timed out: %+v, %v", result, err)
	}
}

func TestInstallSkillsRefusesPathsOutsideTheSkill(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "skills")
	for _, path := range []string{"../escape", "/etc/escape", "a/../../escape", "", "a\\..\\..\\escape", "."} {
		result := install(t, InstallOptions{Dir: dir}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x"), skillFile(path, "0644", "x")))
		if result.Installed != 0 || len(result.Failed) != 1 {
			t.Fatalf("%q was accepted", path)
		}
	}
	if exists(filepath.Join(base, "escape")) {
		t.Fatal("a file was written outside the skill")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("a refused install left %d entries behind", len(entries))
	}
}

func TestInstallSkillsNeverWritesThroughAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	result := install(t, InstallOptions{Dir: dir}, sessionSkill("code-review",
		skillFile("SKILL.md", "0644", "first"),
		skillFile("SKILL.md", "0644", "second"),
	))
	if result.Installed != 0 {
		t.Fatal("a second file at the same path was written over the first")
	}
	if exists(filepath.Join(dir, "code-review")) {
		t.Fatal("a refused install was left behind")
	}

	skill := filepath.Join(t.TempDir(), "skill")
	mkdir(t, skill)
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSkillFolder(skill, sessionSkill("skill", skillFile("SKILL.md", "0644", "ours"))); err == nil {
		t.Fatal("a folder that already exists was written into")
	}
	if got := readFile(t, filepath.Join(skill, "SKILL.md")); got != "untouched" {
		t.Fatalf("an existing file was overwritten: %q", got)
	}
}

func TestInstallSkillsRefusesNamesThatAreNotFolders(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "skills")
	mkdir(t, filepath.Join(base, "keep"))
	for _, name := range []string{"..", "../keep", "a/b", ".hidden", ""} {
		result := install(t, InstallOptions{Dir: dir}, sessionSkill(name, skillFile("SKILL.md", "0644", "x")))
		if result.Installed != 0 {
			t.Fatalf("%q was installed", name)
		}
	}
	if !exists(filepath.Join(base, "keep")) {
		t.Fatal("a folder outside the install folder was removed")
	}
}

func TestInstallSkillsMasksModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes")
	}
	dir := t.TempDir()
	install(t, InstallOptions{Dir: dir}, sessionSkill("code-review",
		skillFile("SKILL.md", "0666", "x"),
		skillFile("scripts/run.sh", "4777", "#!/bin/sh"),
	))
	for path, want := range map[string]os.FileMode{"SKILL.md": 0o644, "scripts/run.sh": 0o755} {
		info, err := os.Stat(filepath.Join(dir, "code-review", path))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode() != want {
			t.Fatalf("%s has mode %v, want %v", path, info.Mode(), want)
		}
	}
}

func TestInstallSkillsKeepsTheUsersFolderInTheInstallFolder(t *testing.T) {
	home := isolateHome(t)
	userSkill := filepath.Join(home, ".agents", "skills", "code-review")
	mkdir(t, userSkill)
	if err := os.WriteFile(filepath.Join(userSkill, "SKILL.md"), []byte("---\nname: code-review\n---\nmine"), 0o644); err != nil {
		t.Fatal(err)
	}
	mkdir(t, filepath.Join(home, ".claude"))

	result := install(t, InstallOptions{}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "ours")))
	if got := readFile(t, filepath.Join(userSkill, "SKILL.md")); got != "---\nname: code-review\n---\nmine" {
		t.Fatalf("the user's SKILL.md was changed: %q", got)
	}
	want := []string{"code-review (a folder named code-review already exists and wasn't installed by Infisical)"}
	if result.Installed != 0 || !reflect.DeepEqual(result.Failed, want) || len(result.Linked) != 0 {
		t.Fatalf("result %+v", result)
	}
	if exists(filepath.Join(home, ".claude", "skills", "code-review")) {
		t.Fatal("a skill that was not installed was linked")
	}
}

func TestInstallSkillsIntoTheWorkingFolderKeepsItsFolders(t *testing.T) {
	project := t.TempDir()
	mkdir(t, filepath.Join(project, "src"))
	if err := os.WriteFile(filepath.Join(project, "src", "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	result := install(t, InstallOptions{Dir: "."}, sessionSkill("src", skillFile("SKILL.md", "0644", "ours")), sessionSkill("deploy", skillFile("SKILL.md", "0644", "d")))
	if got := readFile(t, filepath.Join(project, "src", "main.go")); got != "package main" {
		t.Fatalf("main.go %q", got)
	}
	if exists(filepath.Join(project, "src", "SKILL.md")) {
		t.Fatal("the skill was written into the project's folder")
	}
	want := []string{"src (a folder named src already exists and wasn't installed by Infisical)"}
	if result.Installed != 1 || !reflect.DeepEqual(result.Failed, want) {
		t.Fatalf("result %+v", result)
	}
}

func TestInstallSkillsMarksEveryFolderItWrites(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude"))
	refuse := func(string, string) error { return errors.New("links are not allowed") }
	skill := sessionSkill("code-review", skillFile("SKILL.md", "0644", "x"))
	skill.ID = "skill-id"

	install(t, InstallOptions{Symlink: refuse}, skill)
	for _, folder := range []string{
		filepath.Join(home, ".agents", "skills", "code-review"),
		filepath.Join(home, ".claude", "skills", "code-review"),
	} {
		var marker skillMarker
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(folder, SkillMarkerFile))), &marker); err != nil {
			t.Fatal(err)
		}
		if marker != (skillMarker{SkillID: "skill-id", Sha256: skill.Sha256}) {
			t.Fatalf("%s: marker %+v", folder, marker)
		}
	}
}

func TestInstallSkillsLeavesAnUnchangedSkillAlone(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude"))
	refuse := func(string, string) error { return errors.New("links are not allowed") }
	skill := sessionSkill("code-review", skillFile("SKILL.md", "0644", "x"))
	install(t, InstallOptions{Symlink: refuse}, skill)

	paths := []string{
		filepath.Join(home, ".agents", "skills", "code-review", "SKILL.md"),
		filepath.Join(home, ".claude", "skills", "code-review", "SKILL.md"),
	}
	before := make([]os.FileInfo, len(paths))
	for i, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		before[i] = info
	}
	time.Sleep(20 * time.Millisecond)

	result := install(t, InstallOptions{Symlink: refuse}, skill)
	if result.Installed != 1 || len(result.LinkFailed) != 0 {
		t.Fatalf("result %+v", result)
	}
	for i, path := range paths {
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before[i], after) || !after.ModTime().Equal(before[i].ModTime()) {
			t.Fatalf("%s was rewritten", path)
		}
	}

	install(t, InstallOptions{Symlink: refuse}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "y")))
	for _, path := range paths {
		if got := readFile(t, path); got != "y" {
			t.Fatalf("%s: a changed skill was not rewritten: %q", path, got)
		}
	}
}

func TestInstallSkillsRewritesAFolderCutShort(t *testing.T) {
	dir := t.TempDir()
	skill := sessionSkill("code-review", skillFile("SKILL.md", "0644", "x"), skillFile("scripts/run.sh", "0755", "y"))
	dest := filepath.Join(dir, "code-review")
	mkdir(t, dest)
	if err := os.WriteFile(filepath.Join(dest, SkillMarkerFile), []byte(`{"skillId":"","sha256":""}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if result := install(t, InstallOptions{Dir: dir}, skill); result.Installed != 1 {
		t.Fatalf("result %+v", result)
	}
	if got := readFile(t, filepath.Join(dest, "scripts", "run.sh")); got != "y" {
		t.Fatalf("run.sh %q", got)
	}
}

func TestInstallSkillsRepairsAFileAnAgentChanged(t *testing.T) {
	dir := t.TempDir()
	skill := sessionSkill("code-review",
		skillFile("SKILL.md", "0644", "x"),
		skillFile("scripts/run.sh", "0755", "y"),
		skillFile("scripts/lint.sh", "0755", "z"))
	install(t, InstallOptions{Dir: dir}, skill)
	dest := filepath.Join(dir, "code-review")

	if err := os.Remove(filepath.Join(dest, "scripts", "run.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(dest, "scripts", "lint.sh"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if result := install(t, InstallOptions{Dir: dir}, skill); result.Installed != 1 {
		t.Fatalf("result %+v", result)
	}
	if got := readFile(t, filepath.Join(dest, "scripts", "run.sh")); got != "y" {
		t.Fatalf("run.sh %q", got)
	}
	if got := readFile(t, filepath.Join(dest, "SKILL.md")); got != "x" {
		t.Fatalf("SKILL.md %q", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dest, "scripts", "lint.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("lint.sh mode %v", info.Mode().Perm())
		}
	}
}

func TestInstallSkillsKeepsAFileAnAgentAdded(t *testing.T) {
	dir := t.TempDir()
	skill := sessionSkill("code-review", skillFile("SKILL.md", "0644", "x"))
	install(t, InstallOptions{Dir: dir}, skill)
	notes := filepath.Join(dir, "code-review", "notes.md")
	if err := os.WriteFile(notes, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}

	install(t, InstallOptions{Dir: dir}, skill)
	if got := readFile(t, notes); got != "mine" {
		t.Fatalf("notes.md %q", got)
	}
}

func TestInstallSkillsWithoutALockWhenTheDataFolderIsReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a read-only folder does not stop this user from writing")
	}
	readOnly := t.TempDir()
	if err := os.Chmod(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })
	old := skillsLockDir
	skillsLockDir = func() (string, error) { return filepath.Join(readOnly, "agent-vault"), nil }
	t.Cleanup(func() { skillsLockDir = old })

	dir := t.TempDir()
	if result := install(t, InstallOptions{Dir: dir}, sessionSkill("code-review", skillFile("SKILL.md", "0644", "x"))); result.Installed != 1 {
		t.Fatalf("result %+v", result)
	}
	if got := readFile(t, filepath.Join(dir, "code-review", "SKILL.md")); got != "x" {
		t.Fatalf("SKILL.md %q", got)
	}
}

func TestConcurrentInstallsLeaveEverySkillWhole(t *testing.T) {
	home := isolateHome(t)
	mkdir(t, filepath.Join(home, ".claude"))
	versions := make([][]api.AgentVaultSessionSkill, 4)
	for i := range versions {
		for _, name := range []string{"code-review", "deploy"} {
			files := []api.AgentVaultSkillFile{skillFile("SKILL.md", "0644", fmt.Sprintf("%s v%d", name, i))}
			for f := 0; f < 20; f++ {
				files = append(files, skillFile(fmt.Sprintf("refs/%d.md", f), "0644", fmt.Sprintf("v%d", i)))
			}
			versions[i] = append(versions[i], sessionSkill(name, files...))
		}
	}

	var wg sync.WaitGroup
	results := make([]InstallResult, len(versions)*3)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := InstallSkills(context.Background(), versions[i%len(versions)], InstallOptions{})
			if err != nil {
				t.Error(err)
			}
			results[i] = result
		}(i)
	}
	wg.Wait()

	for i, result := range results {
		if result.Installed != 2 || len(result.Failed) != 0 || len(result.LinkFailed) != 0 {
			t.Fatalf("run %d: %+v", i, result)
		}
	}
	for _, name := range []string{"code-review", "deploy"} {
		folder := filepath.Join(home, ".agents", "skills", name)
		var marker skillMarker
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(folder, SkillMarkerFile))), &marker); err != nil {
			t.Fatal(err)
		}
		var want *api.AgentVaultSessionSkill
		for v := range versions {
			for s := range versions[v] {
				if versions[v][s].Name == name && versions[v][s].Sha256 == marker.Sha256 {
					want = &versions[v][s]
				}
			}
		}
		if want == nil {
			t.Fatalf("%s: the marker names no version that was installed", name)
		}
		for _, file := range want.Files {
			content, _ := base64.StdEncoding.DecodeString(file.ContentBase64)
			if got := readFile(t, filepath.Join(folder, filepath.FromSlash(file.Path))); got != string(content) {
				t.Fatalf("%s/%s: %q, want %q", name, file.Path, got, content)
			}
		}
		assertLinked(t, filepath.Join(home, ".claude", "skills", name), folder)
	}
}
