package util

import (
	"errors"

	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestResolveEnvironmentNameWithSource(t *testing.T) {
	cases := []struct {
		name, workspace, envVar, flag, branch string
		wantValue, wantSource                 string
	}{
		{name: "flag", workspace: `{"defaultEnvironment":"fromfile"}`, envVar: "fromenv", flag: "fromflag", wantValue: "fromflag", wantSource: "--env flag"},
		{name: "environment variable", workspace: `{"defaultEnvironment":"fromfile"}`, envVar: "fromenv", wantValue: "fromenv", wantSource: "INFISICAL_ENVIRONMENT environment variable"},
		{name: "git-branch override", workspace: `{"defaultEnvironment":"fromfile","gitBranchToEnvironmentMapping":{"main":"prod"}}`, branch: "main", wantValue: "prod", wantSource: `.infisical.json git-branch override (branch "main")`},
		{name: "unmapped branch", workspace: `{"defaultEnvironment":"fromfile","gitBranchToEnvironmentMapping":{"main":"prod"}}`, branch: "feature", wantValue: "fromfile", wantSource: ".infisical.json"},
		{name: "config file", workspace: `{"defaultEnvironment":"fromfile"}`, wantValue: "fromfile", wantSource: ".infisical.json"},
		{name: "default", workspace: `{"workspaceId":"p"}`, wantValue: "dev", wantSource: SettingSourceDefault},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			writeWorkspace(t, c.workspace)
			t.Setenv(INFISICAL_ENVIRONMENT_NAME, c.envVar)
			if c.branch != "" {
				mockCurrentBranch(t, c.branch)
			}
			cmd := &cobra.Command{}
			cmd.Flags().String("env", "dev", "")
			if c.flag != "" {
				_ = cmd.Flags().Set("env", c.flag)
			}
			value, source := ResolveEnvironmentNameWithSource(cmd)
			if value != c.wantValue || source != c.wantSource {
				t.Errorf("got (%q, %q), want (%q, %q)", value, source, c.wantValue, c.wantSource)
			}
			if got := ResolveEnvironmentName(cmd); got != value {
				t.Errorf("ResolveEnvironmentName = %q, WithSource = %q", got, value)
			}
		})
	}
}

func TestResolveSecretPathWithSource(t *testing.T) {
	writeWorkspaceYaml(t, "secrets-management:\n  secret-path: /fromfile\n")
	t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
	if value, source := ResolveSecretPathWithSource(newResolveTestCmd(t)); value != "/fromfile" || source != ".infisical.yaml" {
		t.Errorf("config file: got (%q, %q)", value, source)
	}
	t.Setenv(INFISICAL_SECRET_PATH_NAME, "/fromenv")
	if value, source := ResolveSecretPathWithSource(newResolveTestCmd(t)); value != "/fromenv" || source != "INFISICAL_SECRET_PATH environment variable" {
		t.Errorf("environment variable: got (%q, %q)", value, source)
	}
	cmd := newResolveTestCmd(t)
	_ = cmd.Flags().Set("path", "/fromflag")
	if value, source := ResolveSecretPathWithSource(cmd); value != "/fromflag" || source != "--path flag" {
		t.Errorf("flag: got (%q, %q)", value, source)
	}
	t.Chdir(t.TempDir())
	t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
	if value, source := ResolveSecretPathWithSource(newResolveTestCmd(t)); value != "/" || source != SettingSourceDefault {
		t.Errorf("default: got (%q, %q)", value, source)
	}
}

func TestResolveProjectIDWithSource(t *testing.T) {
	newCmd := func(flag string) *cobra.Command {
		cmd := &cobra.Command{}
		cmd.Flags().String("projectId", "", "")
		if flag != "" {
			_ = cmd.Flags().Set("projectId", flag)
		}
		return cmd
	}
	writeWorkspaceYaml(t, "secrets-management:\n  project-id: fromfile\n")

	t.Setenv(INFISICAL_PROJECT_ID_NAME, "fromenv")
	if id, source, err := ResolveProjectIDWithSource(newCmd("fromflag")); id != "fromflag" || source != "--projectId flag" || err != nil {
		t.Errorf("flag: got (%q, %q, %v)", id, source, err)
	}
	if id, source, err := ResolveProjectIDWithSource(newCmd("")); id != "fromenv" || source != "INFISICAL_PROJECT_ID environment variable" || err != nil {
		t.Errorf("environment variable: got (%q, %q, %v)", id, source, err)
	}
	t.Setenv(INFISICAL_PROJECT_ID_NAME, "")
	if id, source, err := ResolveProjectIDWithSource(newCmd("")); id != "fromfile" || source != ".infisical.yaml" || err != nil {
		t.Errorf("config file: got (%q, %q, %v)", id, source, err)
	}

	t.Run("none", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if id, source, err := ResolveProjectIDWithSource(newCmd("")); id != "" || source != "" || err != nil {
			t.Errorf("got (%q, %q, %v)", id, source, err)
		}
	})

	t.Run("config file without a project", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  environment: dev\n")
		if id, source, err := ResolveProjectIDWithSource(newCmd("")); id != "" || source != "" || err != nil {
			t.Errorf("got (%q, %q, %v)", id, source, err)
		}
	})

	t.Run("unreadable config file", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management: [\n")
		_, _, err := ResolveProjectIDWithSource(newCmd(""))
		var configErr *WorkspaceConfigError
		if !errors.As(err, &configErr) || filepath.Base(configErr.Path) != INFISICAL_WORKSPACE_CONFIG_FILE_NAME {
			t.Errorf("got %v", err)
		}
	})

	t.Run("a command without --projectId still reads the rest", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  project-id: fromfile\n")
		if id, _, err := ResolveProjectIDWithSource(&cobra.Command{}); id != "fromfile" || err != nil {
			t.Errorf("got (%q, %v)", id, err)
		}
	})
}
