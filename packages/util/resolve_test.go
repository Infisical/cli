package util

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
)

// newResolveTestCmd builds a command with the flags the resolvers read. Passing a non-empty
// value marks that flag as explicitly set (Changed == true), mirroring a user-passed flag.
func newResolveTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("proxy", "", "")
	cmd.Flags().StringP("env", "e", "", "")
	cmd.Flags().String("path", "/", "")
	cmd.Flags().Bool("allow", false, "")
	return cmd
}

// writeWorkspace drops a legacy .infisical.json into an isolated cwd so file-fallback is
// deterministic.
func writeWorkspace(t *testing.T, contents string) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(contents), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}
}

// writeWorkspaceYaml drops a .infisical.yaml into an isolated cwd so file-fallback is deterministic.
func writeWorkspaceYaml(t *testing.T, contents string) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), []byte(contents), 0o600); err != nil {
		t.Fatalf("write workspace yaml: %v", err)
	}
}

// mockCurrentBranch makes getCurrentBranch report branch for the rest of the test.
func mockCurrentBranch(t *testing.T, branch string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("echo is a shell builtin on windows, not an executable")
	}
	original := getCurrentBranchCmd
	getCurrentBranchCmd = execCmd{cmd: "echo", args: []string{branch}}
	t.Cleanup(func() { getCurrentBranchCmd = original })
}

func TestResolveEnvironmentName(t *testing.T) {
	t.Run("flag wins over env and file", func(t *testing.T) {
		writeWorkspace(t, `{"defaultEnvironment":"fromfile"}`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "fromenv")
		cmd := newResolveTestCmd(t)
		_ = cmd.Flags().Set("env", "fromflag")
		if got := ResolveEnvironmentName(cmd); got != "fromflag" {
			t.Fatalf("got %q, want fromflag", got)
		}
	})

	t.Run("env wins over file when flag unset", func(t *testing.T) {
		writeWorkspace(t, `{"defaultEnvironment":"fromfile"}`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "fromenv")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromenv" {
			t.Fatalf("got %q, want fromenv", got)
		}
	})

	t.Run("file used when flag and env unset", func(t *testing.T) {
		writeWorkspace(t, `{"defaultEnvironment":"fromfile"}`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromfile" {
			t.Fatalf("got %q, want fromfile", got)
		}
	})

	t.Run("flag default is the final fallback", func(t *testing.T) {
		t.Chdir(t.TempDir()) // no workspace file
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})

	t.Run("flag wins over env and yaml file", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-environment: fromyaml\n")
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "fromenv")
		cmd := newResolveTestCmd(t)
		_ = cmd.Flags().Set("env", "fromflag")
		if got := ResolveEnvironmentName(cmd); got != "fromflag" {
			t.Fatalf("got %q, want fromflag", got)
		}
	})

	t.Run("env wins over yaml file when flag unset", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-environment: fromyaml\n")
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "fromenv")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromenv" {
			t.Fatalf("got %q, want fromenv", got)
		}
	})

	t.Run("yaml default-environment used when flag and env unset", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-environment: fromyaml\n")
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromyaml" {
			t.Fatalf("got %q, want fromyaml", got)
		}
	})

	t.Run("yaml git-branch mapping wins over default-environment", func(t *testing.T) {
		mockCurrentBranch(t, "main")
		writeWorkspaceYaml(t, `secrets-management:
  default-environment: fromyaml
  mappings:
    git-branch-to-environment:
      main: frombranch
`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "frombranch" {
			t.Fatalf("got %q, want frombranch", got)
		}
	})

	t.Run("yaml default-environment used when the branch has no mapping", func(t *testing.T) {
		mockCurrentBranch(t, "feature")
		writeWorkspaceYaml(t, `secrets-management:
  default-environment: fromyaml
  mappings:
    git-branch-to-environment:
      main: frombranch
`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromyaml" {
			t.Fatalf("got %q, want fromyaml", got)
		}
	})

	t.Run("yaml environment used when flag and env unset", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  environment: fromyaml\n")
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromyaml" {
			t.Fatalf("got %q, want fromyaml", got)
		}
	})

	t.Run("yaml environment wins over the deprecated default-environment", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-environment: fromdeprecated\n  environment: fromyaml\n")
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromyaml" {
			t.Fatalf("got %q, want fromyaml", got)
		}
	})

	t.Run("yaml git-branch override wins over environment", func(t *testing.T) {
		mockCurrentBranch(t, "main")
		writeWorkspaceYaml(t, `secrets-management:
  environment: fromyaml
  overrides:
    git-branch:
      - branch: main
        environment: frombranch
`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "frombranch" {
			t.Fatalf("got %q, want frombranch", got)
		}
	})

	t.Run("yaml environment used when the branch has no override", func(t *testing.T) {
		mockCurrentBranch(t, "feature")
		writeWorkspaceYaml(t, `secrets-management:
  environment: fromyaml
  overrides:
    git-branch:
      - branch: main
        environment: frombranch
`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromyaml" {
			t.Fatalf("got %q, want fromyaml", got)
		}
	})

	t.Run("yaml git-branch override matches the last segment of the branch", func(t *testing.T) {
		mockCurrentBranch(t, "feature/login")
		writeWorkspaceYaml(t, `secrets-management:
  environment: fromyaml
  overrides:
    git-branch:
      - branch: login
        environment: frombranch
`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "frombranch" {
			t.Fatalf("got %q, want frombranch", got)
		}
	})

	t.Run("yaml deprecated default-environment used when only overrides are set and the branch has no override", func(t *testing.T) {
		mockCurrentBranch(t, "main")
		writeWorkspaceYaml(t, `secrets-management:
  default-environment: fromyaml
  overrides:
    git-branch:
      - branch: feature/x
        environment: frombranch
`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromyaml" {
			t.Fatalf("got %q, want fromyaml", got)
		}
	})

	t.Run("deprecated yaml mapping still matches the last segment of the branch", func(t *testing.T) {
		mockCurrentBranch(t, "feature/login")
		writeWorkspaceYaml(t, `secrets-management:
  default-environment: fromyaml
  mappings:
    git-branch-to-environment:
      login: frombranch
`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "frombranch" {
			t.Fatalf("got %q, want frombranch", got)
		}
	})

	t.Run("legacy json mapping still matches the last segment of the branch", func(t *testing.T) {
		mockCurrentBranch(t, "feature/login")
		writeWorkspace(t, `{"defaultEnvironment":"fromfile","gitBranchToEnvironmentMapping":{"login":"frombranch"}}`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "frombranch" {
			t.Fatalf("got %q, want frombranch", got)
		}
	})

	t.Run("legacy json is read without being migrated", func(t *testing.T) {
		writeWorkspace(t, `{"defaultEnvironment":"fromfile"}`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromfile" {
			t.Fatalf("got %q, want fromfile", got)
		}
		if !fileExists(LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME) {
			t.Fatalf("legacy %s should not be removed", LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		}
		if fileExists(INFISICAL_WORKSPACE_CONFIG_FILE_NAME) {
			t.Fatalf("%s should not be created", INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		}
		// the second resolve still reads the legacy json
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromfile" {
			t.Fatalf("got %q on the second resolve, want fromfile", got)
		}
	})

	t.Run("yaml file wins over legacy json in the same directory", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-environment: fromyaml\n")
		writeTestFile(t, LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME, `{"defaultEnvironment":"fromjson"}`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromyaml" {
			t.Fatalf("got %q, want fromyaml", got)
		}
	})
}

func TestResolveSecretPath(t *testing.T) {
	t.Run("flag wins", func(t *testing.T) {
		writeWorkspace(t, `{"defaultSecretPath":"/fromfile"}`)
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "/fromenv")
		cmd := newResolveTestCmd(t)
		_ = cmd.Flags().Set("path", "/fromflag")
		if got := ResolveSecretPath(cmd); got != "/fromflag" {
			t.Fatalf("got %q, want /fromflag", got)
		}
	})

	t.Run("env over file", func(t *testing.T) {
		writeWorkspace(t, `{"defaultSecretPath":"/fromfile"}`)
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "/fromenv")
		if got := ResolveSecretPath(newResolveTestCmd(t)); got != "/fromenv" {
			t.Fatalf("got %q, want /fromenv", got)
		}
	})

	t.Run("file when flag and env unset", func(t *testing.T) {
		writeWorkspace(t, `{"defaultSecretPath":"/fromfile"}`)
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
		if got := ResolveSecretPath(newResolveTestCmd(t)); got != "/fromfile" {
			t.Fatalf("got %q, want /fromfile", got)
		}
	})

	t.Run("defaults to /", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
		if got := ResolveSecretPath(newResolveTestCmd(t)); got != "/" {
			t.Fatalf("got %q, want /", got)
		}
	})

	t.Run("flag wins over env and yaml file", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-secret-path: /fromyaml\n")
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "/fromenv")
		cmd := newResolveTestCmd(t)
		_ = cmd.Flags().Set("path", "/fromflag")
		if got := ResolveSecretPath(cmd); got != "/fromflag" {
			t.Fatalf("got %q, want /fromflag", got)
		}
	})

	t.Run("env over yaml file", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-secret-path: /fromyaml\n")
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "/fromenv")
		if got := ResolveSecretPath(newResolveTestCmd(t)); got != "/fromenv" {
			t.Fatalf("got %q, want /fromenv", got)
		}
	})

	t.Run("yaml default-secret-path when flag and env unset", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-secret-path: /fromyaml\n")
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
		if got := ResolveSecretPath(newResolveTestCmd(t)); got != "/fromyaml" {
			t.Fatalf("got %q, want /fromyaml", got)
		}
	})

	t.Run("yaml secret-path when flag and env unset", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  secret-path: /fromyaml\n")
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
		if got := ResolveSecretPath(newResolveTestCmd(t)); got != "/fromyaml" {
			t.Fatalf("got %q, want /fromyaml", got)
		}
	})

	t.Run("yaml secret-path wins over the deprecated default-secret-path", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-secret-path: /fromdeprecated\n  secret-path: /fromyaml\n")
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
		if got := ResolveSecretPath(newResolveTestCmd(t)); got != "/fromyaml" {
			t.Fatalf("got %q, want /fromyaml", got)
		}
	})

	t.Run("defaults to / when yaml file has no secret path", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  project-id: proj-123\n")
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
		if got := ResolveSecretPath(newResolveTestCmd(t)); got != "/" {
			t.Fatalf("got %q, want /", got)
		}
	})
}

func TestResolveAgentProxyAddress(t *testing.T) {
	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv(INFISICAL_AGENT_PROXY_ADDRESS_NAME, "env:1")
		cmd := newResolveTestCmd(t)
		_ = cmd.Flags().Set("proxy", "flag:1")
		if got := ResolveAgentProxyAddress(cmd); got != "flag:1" {
			t.Fatalf("got %q, want flag:1", got)
		}
	})

	t.Run("env when flag unset", func(t *testing.T) {
		t.Setenv(INFISICAL_AGENT_PROXY_ADDRESS_NAME, "env:1")
		if got := ResolveAgentProxyAddress(newResolveTestCmd(t)); got != "env:1" {
			t.Fatalf("got %q, want env:1", got)
		}
	})

	// The proxy address must never come from .infisical.json (a committed file), or a poisoned
	// value could silently redirect all agent traffic. Prove the file is ignored.
	t.Run("workspace file is not a source", func(t *testing.T) {
		writeWorkspace(t, `{"agentProxyAddress":"file:1"}`)
		t.Setenv(INFISICAL_AGENT_PROXY_ADDRESS_NAME, "")
		if got := ResolveAgentProxyAddress(newResolveTestCmd(t)); got != "" {
			t.Fatalf("got %q, want empty (.infisical.json must not set the proxy address)", got)
		}
	})

	t.Run("yaml workspace file is not a source", func(t *testing.T) {
		writeWorkspaceYaml(t, `general:
  agent-proxy-address: file:1
secrets-management:
  agent-proxy-address: file:1
`)
		t.Setenv(INFISICAL_AGENT_PROXY_ADDRESS_NAME, "")
		if got := ResolveAgentProxyAddress(newResolveTestCmd(t)); got != "" {
			t.Fatalf("got %q, want empty (.infisical.yaml must not set the proxy address)", got)
		}
	})

	t.Run("empty when nothing set", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv(INFISICAL_AGENT_PROXY_ADDRESS_NAME, "")
		if got := ResolveAgentProxyAddress(newResolveTestCmd(t)); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})
}

func TestGetBoolFlagOrEnv(t *testing.T) {
	const env = "INFISICAL_TEST_BOOL"

	t.Run("explicit flag wins", func(t *testing.T) {
		t.Setenv(env, "false")
		cmd := newResolveTestCmd(t)
		_ = cmd.Flags().Set("allow", "true")
		if !GetBoolFlagOrEnv(cmd, "allow", env) {
			t.Fatal("expected true from flag")
		}
	})

	t.Run("env true when flag unset", func(t *testing.T) {
		t.Setenv(env, "true")
		if !GetBoolFlagOrEnv(newResolveTestCmd(t), "allow", env) {
			t.Fatal("expected true from env")
		}
	})

	t.Run("env false when flag unset", func(t *testing.T) {
		t.Setenv(env, "false")
		if GetBoolFlagOrEnv(newResolveTestCmd(t), "allow", env) {
			t.Fatal("expected false from env")
		}
	})

	t.Run("unparseable env fails closed to false", func(t *testing.T) {
		t.Setenv(env, "yeah")
		if GetBoolFlagOrEnv(newResolveTestCmd(t), "allow", env) {
			t.Fatal("expected false on unparseable env")
		}
	})

	t.Run("flag default when nothing set", func(t *testing.T) {
		t.Setenv(env, "")
		if GetBoolFlagOrEnv(newResolveTestCmd(t), "allow", env) {
			t.Fatal("expected false (flag default)")
		}
	})
}

// newRunLikeTestCmd mirrors `run`: a repeatable --path and a --project-config-dir flag.
func newRunLikeTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "run"}
	cmd.Flags().StringP("env", "e", "dev", "")
	cmd.Flags().StringArray("path", []string{"/"}, "")
	cmd.Flags().String("project-config-dir", "", "")
	return cmd
}

func TestResolveSecretPaths(t *testing.T) {
	t.Run("repeated flags win and are returned as given", func(t *testing.T) {
		writeWorkspace(t, `{"defaultSecretPath":"/fromfile"}`)
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "/fromenv")
		cmd := newRunLikeTestCmd(t)
		_ = cmd.Flags().Set("path", "/a")
		_ = cmd.Flags().Set("path", "/b")
		got := ResolveSecretPaths(cmd)
		if len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
			t.Fatalf("got %v, want [/a /b]", got)
		}
	})

	t.Run("env over file", func(t *testing.T) {
		writeWorkspace(t, `{"defaultSecretPath":"/fromfile"}`)
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "/fromenv")
		if got := ResolveSecretPaths(newRunLikeTestCmd(t)); len(got) != 1 || got[0] != "/fromenv" {
			t.Fatalf("got %v, want [/fromenv]", got)
		}
	})

	t.Run("file when flag and env unset", func(t *testing.T) {
		writeWorkspace(t, `{"defaultSecretPath":"/fromfile"}`)
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
		if got := ResolveSecretPaths(newRunLikeTestCmd(t)); len(got) != 1 || got[0] != "/fromfile" {
			t.Fatalf("got %v, want [/fromfile]", got)
		}
	})

	t.Run("defaults to the flag default", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv(INFISICAL_SECRET_PATH_NAME, "")
		if got := ResolveSecretPaths(newRunLikeTestCmd(t)); len(got) != 1 || got[0] != "/" {
			t.Fatalf("got %v, want [/]", got)
		}
	})
}

// A command pointed at another project with --project-config-dir must take its environment and
// path defaults from that project's .infisical.json, never from the one in the current directory.
func TestResolveUsesProjectConfigDir(t *testing.T) {
	writeWorkspace(t, `{"workspaceId":"cwd-project","defaultEnvironment":"cwd-env","defaultSecretPath":"/cwd-path"}`)
	t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
	t.Setenv(INFISICAL_SECRET_PATH_NAME, "")

	selected := t.TempDir()
	if err := os.WriteFile(filepath.Join(selected, ".infisical.json"),
		[]byte(`{"workspaceId":"selected-project","defaultEnvironment":"selected-env","defaultSecretPath":"/selected-path"}`), 0o600); err != nil {
		t.Fatalf("write selected workspace: %v", err)
	}

	t.Run("selected file wins over the current directory", func(t *testing.T) {
		cmd := newRunLikeTestCmd(t)
		_ = cmd.Flags().Set("project-config-dir", selected)
		if got := ResolveEnvironmentName(cmd); got != "selected-env" {
			t.Errorf("environment: got %q, want selected-env", got)
		}
		if got := ResolveSecretPaths(cmd); len(got) != 1 || got[0] != "/selected-path" {
			t.Errorf("paths: got %v, want [/selected-path]", got)
		}
	})

	t.Run("selected file without defaults falls back to the flag defaults, not the cwd file", func(t *testing.T) {
		bare := t.TempDir()
		if err := os.WriteFile(filepath.Join(bare, ".infisical.json"), []byte(`{"workspaceId":"bare"}`), 0o600); err != nil {
			t.Fatalf("write bare workspace: %v", err)
		}
		cmd := newRunLikeTestCmd(t)
		_ = cmd.Flags().Set("project-config-dir", bare)
		if got := ResolveEnvironmentName(cmd); got != "dev" {
			t.Errorf("environment: got %q, want dev", got)
		}
		if got := ResolveSecretPaths(cmd); len(got) != 1 || got[0] != "/" {
			t.Errorf("paths: got %v, want [/]", got)
		}
	})

	t.Run("without the flag the current directory is used", func(t *testing.T) {
		cmd := newRunLikeTestCmd(t)
		if got := ResolveEnvironmentName(cmd); got != "cwd-env" {
			t.Errorf("environment: got %q, want cwd-env", got)
		}
		if got := ResolveSecretPaths(cmd); len(got) != 1 || got[0] != "/cwd-path" {
			t.Errorf("paths: got %v, want [/cwd-path]", got)
		}
	})
}
