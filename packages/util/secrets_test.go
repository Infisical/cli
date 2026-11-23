package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveWorkspaceID(t *testing.T) {
	t.Run("uses explicit project ID before config", func(t *testing.T) {
		workspaceID, err := resolveWorkspaceID("project-from-flag", t.TempDir())
		if err != nil {
			t.Fatalf("resolve workspace ID: %v", err)
		}
		if workspaceID != "project-from-flag" {
			t.Errorf("workspace ID = %q, want %q", workspaceID, "project-from-flag")
		}
	})

	t.Run("uses workspace config when project ID is omitted", func(t *testing.T) {
		configDir := t.TempDir()
		configPath := filepath.Join(configDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		if err := os.WriteFile(configPath, []byte(`{"workspaceId":"project-from-config"}`), 0600); err != nil {
			t.Fatalf("write workspace config: %v", err)
		}

		workspaceID, err := resolveWorkspaceID("", configDir)
		if err != nil {
			t.Fatalf("resolve workspace ID: %v", err)
		}
		if workspaceID != "project-from-config" {
			t.Errorf("workspace ID = %q, want %q", workspaceID, "project-from-config")
		}
	})
}
