package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
)

const migrateConfigTestJSON = `{
	"workspaceId": "proj-123",
	"defaultEnvironment": "dev",
	"gitBranchToEnvironmentMapping": {"main": "prod"},
	"defaultSecretPath": "/backend",
	"domain": "https://eu.infisical.com"
}`

func writeMigrateConfigTestFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertMigratedWorkspaceConfig(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME)); !os.IsNotExist(err) {
		t.Errorf("legacy %s should be removed after migrating [err=%v]", util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME, err)
	}

	cfg, err := util.GetWorkSpaceFromFilePath(dir)
	if err != nil {
		t.Fatalf("GetWorkSpaceFromFilePath: %v", err)
	}
	if cfg.WorkspaceId != "proj-123" || cfg.DefaultEnvironment != "dev" || cfg.DefaultSecretPath != "/backend" ||
		cfg.Domain != "https://eu.infisical.com" || cfg.GitBranchToEnvironmentMapping["main"] != "prod" {
		t.Errorf("migrated config does not match the legacy json: %+v", cfg)
	}
}

func TestMigrateLegacyWorkspaceConfig(t *testing.T) {
	t.Run("migrates the json in the current directory", func(t *testing.T) {
		dir := isolateWorkspaceDir(t)
		writeMigrateConfigTestFile(t, filepath.Join(dir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME), migrateConfigTestJSON)

		if err := migrateLegacyWorkspaceConfig(); err != nil {
			t.Fatalf("migrateLegacyWorkspaceConfig: %v", err)
		}
		assertMigratedWorkspaceConfig(t, dir)
	})

	t.Run("migrates the json found in a parent directory", func(t *testing.T) {
		dir := isolateWorkspaceDir(t)
		writeMigrateConfigTestFile(t, filepath.Join(dir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME), migrateConfigTestJSON)
		nested := filepath.Join(dir, "a", "b")
		if err := os.MkdirAll(nested, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		t.Chdir(nested)

		if err := migrateLegacyWorkspaceConfig(); err != nil {
			t.Fatalf("migrateLegacyWorkspaceConfig: %v", err)
		}
		assertMigratedWorkspaceConfig(t, dir)
		if _, err := os.Stat(filepath.Join(nested, util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)); !os.IsNotExist(err) {
			t.Errorf("yaml should be written next to the json, not in the current directory [err=%v]", err)
		}
	})

	t.Run("does nothing when the project already uses yaml", func(t *testing.T) {
		dir := isolateWorkspaceDir(t)
		jsonPath := filepath.Join(dir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
		yamlPath := filepath.Join(dir, util.INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME)
		const existingYAML = "secrets-management:\n  project-id: proj-yaml\n"
		writeMigrateConfigTestFile(t, jsonPath, migrateConfigTestJSON)
		writeMigrateConfigTestFile(t, yamlPath, existingYAML)

		if err := migrateLegacyWorkspaceConfig(); err != nil {
			t.Fatalf("migrateLegacyWorkspaceConfig: %v", err)
		}

		raw, err := os.ReadFile(yamlPath)
		if err != nil {
			t.Fatalf("read %s: %v", yamlPath, err)
		}
		if string(raw) != existingYAML {
			t.Errorf("existing yaml was modified:\n%s", raw)
		}
		if _, err := os.Stat(jsonPath); err != nil {
			t.Errorf("leftover json should not be touched [err=%v]", err)
		}
	})

	t.Run("errors when there is no workspace config", func(t *testing.T) {
		isolateWorkspaceDir(t)

		if err := migrateLegacyWorkspaceConfig(); err == nil {
			t.Fatal("expected an error when no workspace config exists")
		}
	})
}
