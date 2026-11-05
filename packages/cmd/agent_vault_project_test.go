package cmd

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

const (
	projectFromFlag    = "11111111-1111-4111-8111-111111111111"
	projectFromAgvEnv  = "22222222-2222-4222-8222-222222222222"
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

func isolateAgentVaultProject(t *testing.T) {
	t.Helper()
	t.Setenv(agentVaultProjectIDEnv, "")
	t.Setenv(util.INFISICAL_PROJECT_ID_NAME, "")
}

func TestResolveAgentVaultProjectOrder(t *testing.T) {
	isolateAgentVaultProject(t)
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
		{nil, projectFromProjEnv, util.INFISICAL_PROJECT_ID_NAME, nil},
	}
	for _, step := range steps {
		project, err := resolveAgentVaultProject(projectIDCmd(t, step.args...))
		if err != nil {
			t.Fatal(err)
		}
		if project.ID != step.wantID || project.Source != step.wantSource {
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

func TestResolveAgentVaultProjectLowercasesTheID(t *testing.T) {
	isolateAgentVaultProject(t)

	const upper = "ABCDEF12-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
	want := strings.ToLower(upper)
	sources := []struct {
		name string
		set  func() *cobra.Command
	}{
		{"--project-id", func() *cobra.Command { return projectIDCmd(t, "--project-id", upper) }},
		{agentVaultProjectIDEnv, func() *cobra.Command { t.Setenv(agentVaultProjectIDEnv, upper); return projectIDCmd(t) }},
		{util.INFISICAL_PROJECT_ID_NAME, func() *cobra.Command {
			t.Setenv(agentVaultProjectIDEnv, "")
			t.Setenv(util.INFISICAL_PROJECT_ID_NAME, upper)
			return projectIDCmd(t)
		}},
	}
	for _, source := range sources {
		project, err := resolveAgentVaultProject(source.set())
		if err != nil {
			t.Fatalf("%s: %v", source.name, err)
		}
		if project.Source != source.name || project.ID != want {
			t.Fatalf("%s: got %s from %s, want %s", source.name, project.ID, project.Source, want)
		}
	}
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
	isolateAgentVaultProject(t)

	if _, err := resolveAgentVaultProject(projectIDCmd(t, "--project-id", "my-project")); err == nil || !strings.Contains(err.Error(), `"my-project" from --project-id`) {
		t.Fatalf("flag: %v", err)
	}

	t.Setenv(util.INFISICAL_PROJECT_ID_NAME, "{"+projectFromProjEnv+"}")
	if _, err := resolveAgentVaultProject(projectIDCmd(t)); err == nil || !strings.Contains(err.Error(), "from "+util.INFISICAL_PROJECT_ID_NAME) {
		t.Fatalf("braced uuid from %s: %v", util.INFISICAL_PROJECT_ID_NAME, err)
	}

	t.Setenv(agentVaultProjectIDEnv, "my-agent-vault")
	if _, err := resolveAgentVaultProject(projectIDCmd(t)); err == nil || !strings.Contains(err.Error(), `"my-agent-vault" from `+agentVaultProjectIDEnv) {
		t.Fatalf("%s: %v", agentVaultProjectIDEnv, err)
	}
}

func TestResolveAgentVaultProjectWithNothingSetNamesEverySource(t *testing.T) {
	isolateAgentVaultProject(t)

	_, err := resolveAgentVaultProject(projectIDCmd(t))
	if err == nil {
		t.Fatal("want an error when no project is set")
	}
	for _, source := range []string{"--project-id", agentVaultProjectIDEnv, util.INFISICAL_PROJECT_ID_NAME} {
		if !strings.Contains(err.Error(), source) {
			t.Errorf("the message should name %s: %q", source, err)
		}
	}
	if strings.Contains(err.Error(), util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME) {
		t.Errorf("the message should not offer a project file: %q", err)
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

func captureAgentVaultStdout(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := util.GetStdoutWriter
	util.GetStdoutWriter = func() io.Writer { return &buf }
	t.Cleanup(func() { util.GetStdoutWriter = old })
	return &buf
}

func TestPrintAgentVaultProjectForProfile(t *testing.T) {
	isolateAgentVaultProject(t)

	out := captureAgentVaultStdout(t)
	printAgentVaultProjectForProfile()
	if out.Len() != 0 {
		t.Fatalf("nothing set should print nothing, printed %q", out)
	}

	t.Setenv(util.INFISICAL_PROJECT_ID_NAME, projectFromProjEnv)
	t.Setenv(agentVaultProjectIDEnv, projectFromAgvEnv)
	printAgentVaultProjectForProfile()
	if want := "Agent Vault project: " + projectFromAgvEnv + "\nAgent Vault project via: " + agentVaultProjectIDEnv + "\n"; out.String() != want {
		t.Fatalf("printed %q, want %q", out, want)
	}

	out.Reset()
	t.Setenv(agentVaultProjectIDEnv, "my-agent-vault")
	printAgentVaultProjectForProfile()
	if !strings.HasPrefix(out.String(), "Agent Vault project: ") || !strings.Contains(out.String(), `"my-agent-vault" from `+agentVaultProjectIDEnv) {
		t.Fatalf("printed %q", out)
	}
}

func TestAgentVaultProjectSourceKind(t *testing.T) {
	for source, want := range map[string]string{
		"--project-id":                 "flag",
		agentVaultProjectIDEnv:         "agent-vault-env",
		util.INFISICAL_PROJECT_ID_NAME: "project-env",
	} {
		if got := agentVaultProjectSourceKind(agentVaultProject{Source: source}); got != want {
			t.Errorf("%s: got %s, want %s", source, got, want)
		}
	}
}
