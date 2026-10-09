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
// deterministic. The first read migrates it to .infisical.yaml.
func writeWorkspace(t *testing.T, contents string) {
	t.Helper()
	useTempHome(t)
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
	if err := os.WriteFile(filepath.Join(dir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME), []byte(contents), 0o600); err != nil {
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

	t.Run("legacy json is migrated to yaml on first resolve", func(t *testing.T) {
		writeWorkspace(t, `{"defaultEnvironment":"fromfile"}`)
		t.Setenv(INFISICAL_ENVIRONMENT_NAME, "")
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromfile" {
			t.Fatalf("got %q, want fromfile", got)
		}
		if fileExists(INFISICAL_WORKSPACE_CONFIG_FILE_NAME) {
			t.Fatalf("legacy %s should have been removed", INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		}
		if !fileExists(INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME) {
			t.Fatalf("%s should have been created", INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		}
		// the second resolve reads the migrated yaml
		if got := ResolveEnvironmentName(newResolveTestCmd(t)); got != "fromfile" {
			t.Fatalf("got %q after migration, want fromfile", got)
		}
	})

	t.Run("yaml file wins over legacy json in the same directory", func(t *testing.T) {
		writeWorkspaceYaml(t, "secrets-management:\n  default-environment: fromyaml\n")
		writeTestFile(t, INFISICAL_WORKSPACE_CONFIG_FILE_NAME, `{"defaultEnvironment":"fromjson"}`)
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

	t.Run("defaults to / when yaml file has no default-secret-path", func(t *testing.T) {
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
