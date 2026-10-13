package util

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateHomeDir points the home dir at a temp dir. os.UserHomeDir reads HOME on Unix
// and USERPROFILE on Windows, so both are set.
func isolateHomeDir(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

// setupWorkspaceConfigMigrationNoticeTest points the home dir at a temp dir so the notice cache is isolated,
// chdirs into a fresh project dir, and returns the project dir.
func setupWorkspaceConfigMigrationNoticeTest(t *testing.T) string {
	t.Helper()
	isolateHomeDir(t)
	t.Setenv("INFISICAL_DISABLE_WORKSPACE_CONFIG_MIGRATION_NOTICE", "")
	t.Setenv("INFISICAL_DISABLE_MIGRATION_NOTICES", "")
	projectDir := t.TempDir()
	t.Chdir(projectDir)
	return projectDir
}

func migrationNoticeCachePathForTest(t *testing.T) string {
	t.Helper()
	path, err := getMigrationNoticeCachePath()
	if err != nil {
		t.Fatalf("cache path: %v", err)
	}
	return path
}

func TestWorkspaceConfigMigrationNoticeShownForLegacyJSON(t *testing.T) {
	projectDir := setupWorkspaceConfigMigrationNoticeTest(t)
	jsonPath := filepath.Join(projectDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME)
	writeTestFile(t, jsonPath, legacyWorkspaceJSON)

	var buf bytes.Buffer
	DisplayWorkspaceConfigMigrationNoticeWithWriter(false, &buf)

	out := buf.String()
	for _, want := range []string{
		"Important: .infisical.json is deprecated",
		jsonPath,
		"infisical migrate-config",
		workspaceConfigMigrationGuideURL,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("notice missing %q, got:\n%s", want, out)
		}
	}
	if !fileExists(migrationNoticeCachePathForTest(t)) {
		t.Error("expected the notice cache file to be written")
	}

	buf.Reset()
	DisplayWorkspaceConfigMigrationNoticeWithWriter(false, &buf)
	if buf.Len() != 0 {
		t.Errorf("expected no notice within the TTL, got:\n%s", buf.String())
	}
}

func TestWorkspaceConfigMigrationNoticeShownForLegacyJSONInParentDir(t *testing.T) {
	projectDir := setupWorkspaceConfigMigrationNoticeTest(t)
	writeTestFile(t, filepath.Join(projectDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), legacyWorkspaceJSON)
	nested := filepath.Join(projectDir, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(nested)

	var buf bytes.Buffer
	DisplayWorkspaceConfigMigrationNoticeWithWriter(false, &buf)
	if !strings.Contains(buf.String(), "Important:") {
		t.Errorf("expected the notice for a legacy json in a parent dir, got:\n%s", buf.String())
	}
}

func TestWorkspaceConfigMigrationNoticeNotShown(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, projectDir string)
		isSilent bool
	}{
		{
			name: "yaml only",
			setup: func(t *testing.T, projectDir string) {
				writeTestFile(t, filepath.Join(projectDir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME), workspaceYAML)
			},
		},
		{
			name: "yaml takes precedence over json",
			setup: func(t *testing.T, projectDir string) {
				writeTestFile(t, filepath.Join(projectDir, INFISICAL_NEW_WORKSPACE_CONFIG_FILE_NAME), workspaceYAML)
				writeTestFile(t, filepath.Join(projectDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), legacyWorkspaceJSON)
			},
		},
		{
			name:  "no workspace config",
			setup: func(t *testing.T, projectDir string) {},
		},
		{
			name: "silent",
			setup: func(t *testing.T, projectDir string) {
				writeTestFile(t, filepath.Join(projectDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), legacyWorkspaceJSON)
			},
			isSilent: true,
		},
		{
			name: "disabled by env var",
			setup: func(t *testing.T, projectDir string) {
				writeTestFile(t, filepath.Join(projectDir, INFISICAL_WORKSPACE_CONFIG_FILE_NAME), legacyWorkspaceJSON)
				t.Setenv("INFISICAL_DISABLE_WORKSPACE_CONFIG_MIGRATION_NOTICE", "1")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			projectDir := setupWorkspaceConfigMigrationNoticeTest(t)
			tc.setup(t, projectDir)

			var buf bytes.Buffer
			DisplayWorkspaceConfigMigrationNoticeWithWriter(tc.isSilent, &buf)
			if buf.Len() != 0 {
				t.Errorf("expected no notice, got:\n%s", buf.String())
			}
			if fileExists(migrationNoticeCachePathForTest(t)) {
				t.Error("expected no notice cache file to be written")
			}
		})
	}
}
