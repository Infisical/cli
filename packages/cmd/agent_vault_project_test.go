package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

const (
	projectFromFlag    = "11111111-1111-4111-8111-111111111111"
	projectFromAgvEnv  = "22222222-2222-4222-8222-222222222222"
	projectFromFile    = "33333333-3333-4333-8333-333333333333"
	projectFromProjEnv = "44444444-4444-4444-8444-444444444444"
)

func projectIDCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "create", Run: func(*cobra.Command, []string) {}}
	cmd.Flags().String("project-id", "", "")
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// isolateAgentVaultProject clears every source and moves into an empty folder, so no real .infisical.yaml is read.
func isolateAgentVaultProject(t *testing.T) string {
	t.Helper()
	t.Setenv(agentVaultProjectIDEnv, "")
	t.Setenv(util.INFISICAL_PROJECT_ID_NAME, "")
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

func writeAgentVaultWorkspaceFile(t *testing.T, dir, projectID string) string {
	t.Helper()
	path := filepath.Join(dir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	content := "version: 1\nsecrets-management:\n  project-id: 99999999-9999-4999-8999-999999999999\nagent-vault:\n  project-id: " + projectID + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveAgentVaultProjectOrder(t *testing.T) {
	dir := isolateAgentVaultProject(t)
	path := writeAgentVaultWorkspaceFile(t, dir, projectFromFile)
	t.Setenv(agentVaultProjectIDEnv, projectFromAgvEnv)
	t.Setenv(util.INFISICAL_PROJECT_ID_NAME, projectFromProjEnv)

	steps := []struct {
		args       []string
		wantID     string
		wantSource string
		drop       func()
	}{
		{[]string{"--project-id", projectFromFlag}, projectFromFlag, "--project-id", nil},
		{nil, projectFromAgvEnv, agentVaultProjectIDEnv, func() { t.Setenv(agentVaultProjectIDEnv, "") }},
		{nil, projectFromFile, path, func() {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{nil, projectFromProjEnv, util.INFISICAL_PROJECT_ID_NAME, nil},
	}
	for _, step := range steps {
		project, err := resolveAgentVaultProject(projectIDCmd(t, step.args...))
		if err != nil {
			t.Fatal(err)
		}
		if project.ID != step.wantID || !sameAgentVaultProjectSource(project.Source, step.wantSource) {
			t.Fatalf("got %s from %s, want %s from %s", project.ID, project.Source, step.wantID, step.wantSource)
		}
		if project.FromFlag != (step.wantSource == "--project-id") {
			t.Fatalf("FromFlag = %v for %s", project.FromFlag, project.Source)
		}
		if step.drop != nil {
			step.drop()
		}
	}
}

// The temp folder is reached through a symlink on macOS, so a path source may name it either way.
func sameAgentVaultProjectSource(got, want string) bool {
	if got == want {
		return true
	}
	gotPath, gotErr := filepath.EvalSymlinks(got)
	wantPath, wantErr := filepath.EvalSymlinks(want)
	return gotErr == nil && wantErr == nil && gotPath == wantPath
}

func TestResolveAgentVaultProjectRefusesAnEmptyFlag(t *testing.T) {
	isolateAgentVaultProject(t)
	t.Setenv(agentVaultProjectIDEnv, projectFromAgvEnv)

	_, err := resolveAgentVaultProject(projectIDCmd(t, "--project-id", " "))
	if err == nil || !strings.Contains(err.Error(), "--project-id was given but is empty") {
		t.Fatalf("an explicitly empty --project-id should be an error, not a fall back to the environment: %v", err)
	}
}

func TestResolveAgentVaultProjectRefusesANonUuidNamingItsSource(t *testing.T) {
	dir := isolateAgentVaultProject(t)

	if _, err := resolveAgentVaultProject(projectIDCmd(t, "--project-id", "my-project")); err == nil || !strings.Contains(err.Error(), `"my-project" from --project-id`) {
		t.Fatalf("flag: %v", err)
	}

	t.Setenv(util.INFISICAL_PROJECT_ID_NAME, "{"+projectFromProjEnv+"}")
	if _, err := resolveAgentVaultProject(projectIDCmd(t)); err == nil || !strings.Contains(err.Error(), "from "+util.INFISICAL_PROJECT_ID_NAME) {
		t.Fatalf("braced uuid from %s: %v", util.INFISICAL_PROJECT_ID_NAME, err)
	}

	writeAgentVaultWorkspaceFile(t, dir, "nope")
	if _, err := resolveAgentVaultProject(projectIDCmd(t)); err == nil || !strings.Contains(err.Error(), util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME) {
		t.Fatalf("file: %v", err)
	}
}

func TestResolveAgentVaultProjectWithNothingSetNamesEverySource(t *testing.T) {
	isolateAgentVaultProject(t)

	_, err := resolveAgentVaultProject(projectIDCmd(t))
	if err == nil {
		t.Fatal("want an error when no project is set")
	}
	for _, source := range []string{"--project-id", agentVaultProjectIDEnv, "agent-vault.project-id", util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME, util.INFISICAL_PROJECT_ID_NAME} {
		if !strings.Contains(err.Error(), source) {
			t.Errorf("the message should name %s: %q", source, err)
		}
	}
}

func TestResolveAgentVaultProjectSkipsAFileWithoutAnAgentVaultSection(t *testing.T) {
	dir := isolateAgentVaultProject(t)
	if err := os.WriteFile(filepath.Join(dir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME), []byte("version: 1\nsecrets-management:\n  project-id: abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(util.INFISICAL_PROJECT_ID_NAME, projectFromProjEnv)

	project, err := resolveAgentVaultProject(projectIDCmd(t))
	if err != nil || project.ID != projectFromProjEnv {
		t.Fatalf("got %+v, %v", project, err)
	}
}

func TestAgentVaultProjectHintsOnlyFor404FromTheSharedVariable(t *testing.T) {
	notFound := &api.APIError{StatusCode: 404}
	shared := agentVaultProject{ID: projectFromProjEnv, Source: util.INFISICAL_PROJECT_ID_NAME}

	if hints := agentVaultProjectHints(notFound, shared); len(hints) != 1 || !strings.Contains(hints[0], "Secrets Management") || !strings.Contains(hints[0], agentVaultProjectIDEnv) {
		t.Fatalf("hints %v", hints)
	}
	if hints := agentVaultProjectHints(notFound, agentVaultProject{Source: agentVaultProjectIDEnv}); hints != nil {
		t.Fatalf("a project from %s needs no hint: %v", agentVaultProjectIDEnv, hints)
	}
	if hints := agentVaultProjectHints(&api.APIError{StatusCode: 403}, shared); hints != nil {
		t.Fatalf("a 403 needs no hint: %v", hints)
	}
	if hints := agentVaultProjectHints(&api.APIError{StatusCode: 404, DocumentationURL: "https://infisical.com/docs"}, shared); hints != nil {
		t.Fatalf("a missing route is not a missing project: %v", hints)
	}
}
