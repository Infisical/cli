package util

import (
	"os"
	"path/filepath"
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

// writeWorkspace drops a .infisical.json into an isolated cwd so file-fallback is deterministic.
func writeWorkspace(t *testing.T, contents string) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".infisical.json"), []byte(contents), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}
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
}

func TestResolveAgentProxyAddress(t *testing.T) {
	t.Run("flag wins", func(t *testing.T) {
		writeWorkspace(t, `{"agentProxyAddress":"file:1"}`)
		t.Setenv(INFISICAL_AGENT_PROXY_ADDRESS_NAME, "env:1")
		cmd := newResolveTestCmd(t)
		_ = cmd.Flags().Set("proxy", "flag:1")
		if got := ResolveAgentProxyAddress(cmd); got != "flag:1" {
			t.Fatalf("got %q, want flag:1", got)
		}
	})

	t.Run("env over file", func(t *testing.T) {
		writeWorkspace(t, `{"agentProxyAddress":"file:1"}`)
		t.Setenv(INFISICAL_AGENT_PROXY_ADDRESS_NAME, "env:1")
		if got := ResolveAgentProxyAddress(newResolveTestCmd(t)); got != "env:1" {
			t.Fatalf("got %q, want env:1", got)
		}
	})

	t.Run("file when flag and env unset", func(t *testing.T) {
		writeWorkspace(t, `{"agentProxyAddress":"file:1"}`)
		t.Setenv(INFISICAL_AGENT_PROXY_ADDRESS_NAME, "")
		if got := ResolveAgentProxyAddress(newResolveTestCmd(t)); got != "file:1" {
			t.Fatalf("got %q, want file:1", got)
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
