package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"gopkg.in/yaml.v3"
)

// isolateWorkspaceDir runs the test from an empty directory with a temp home, so the workspace config and its
// lockfile stay out of the repository and the real ~/.infisical.
func isolateWorkspaceDir(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

func TestWriteWorkspaceFile(t *testing.T) {
	t.Run("fresh directory gets only a yaml config", func(t *testing.T) {
		dir := isolateWorkspaceDir(t)

		if err := writeWorkspaceFile(models.Workspace{ID: "proj-new"}); err != nil {
			t.Fatalf("writeWorkspaceFile: %v", err)
		}

		yamlPath := filepath.Join(dir, util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		raw, err := os.ReadFile(yamlPath)
		if err != nil {
			t.Fatalf("read %s: %v", yamlPath, err)
		}
		var written models.WorkspaceConfigFileYaml
		if err := yaml.Unmarshal(raw, &written); err != nil {
			t.Fatalf("%s is not valid yaml: %v\n%s", yamlPath, err, raw)
		}
		if written.SecretsManagement.ProjectID != "proj-new" {
			t.Errorf("secrets-management.project-id = %q, want proj-new", written.SecretsManagement.ProjectID)
		}

		cfg, err := util.GetWorkSpaceFromFile()
		if err != nil {
			t.Fatalf("GetWorkSpaceFromFile: %v", err)
		}
		if cfg.WorkspaceId != "proj-new" {
			t.Errorf("WorkspaceId = %q, want proj-new", cfg.WorkspaceId)
		}

		info, err := os.Stat(yamlPath)
		if err != nil {
			t.Fatalf("stat %s: %v", yamlPath, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("yaml perm = %o, want 600", info.Mode().Perm())
		}

		// no legacy JSON and no leftover temp file
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}
		if len(entries) != 1 || entries[0].Name() != util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME {
			t.Errorf("expected only %s in dir, got %v", util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME, entries)
		}
	})

	t.Run("replaces a legacy json config", func(t *testing.T) {
		dir := isolateWorkspaceDir(t)
		jsonPath := filepath.Join(dir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		if err := os.WriteFile(jsonPath, []byte(`{"workspaceId":"proj-old"}`), 0o600); err != nil {
			t.Fatalf("write json: %v", err)
		}

		if err := writeWorkspaceFile(models.Workspace{ID: "proj-new"}); err != nil {
			t.Fatalf("writeWorkspaceFile: %v", err)
		}

		if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
			t.Errorf("legacy %s should have been removed [stat err=%v]", jsonPath, err)
		}
		cfg, err := util.GetWorkSpaceFromFile()
		if err != nil {
			t.Fatalf("GetWorkSpaceFromFile: %v", err)
		}
		if cfg.WorkspaceId != "proj-new" {
			t.Errorf("WorkspaceId = %q, want proj-new", cfg.WorkspaceId)
		}
	})
}
