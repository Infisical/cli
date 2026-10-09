package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
)

// An expanded fetch and a raw (--expand=false) fetch of the same folder hold different values, so
// their offline backups must not overwrite each other.
func TestBackupSecretsKeepsExpansionModesApart(t *testing.T) {
	key := useTempHome(t)

	expanded := []models.SingleEnvironmentVariable{{Key: "REF", Value: "alpha-ref"}}
	raw := []models.SingleEnvironmentVariable{{Key: "REF", Value: "${A}-ref"}}

	if err := WriteBackupSecrets("ws", "dev", "/app", true, key, expanded); err != nil {
		t.Fatalf("write expanded backup: %v", err)
	}
	if err := WriteBackupSecrets("ws", "dev", "/app", false, key, raw); err != nil {
		t.Fatalf("write raw backup: %v", err)
	}

	for _, tc := range []struct {
		expanded bool
		want     string
	}{{true, "alpha-ref"}, {false, "${A}-ref"}} {
		got, err := ReadBackupSecrets("ws", "dev", "/app", tc.expanded, key)
		if err != nil {
			t.Fatalf("read backup (expanded=%v): %v", tc.expanded, err)
		}
		if len(got) != 1 || got[0].Value != tc.want {
			t.Errorf("backup (expanded=%v) = %+v, want value %q", tc.expanded, got, tc.want)
		}
	}
}

// useTempHome points the CLI's home at a temp dir (HOME on Unix, USERPROFILE on Windows, which is
// what os.UserHomeDir reads there) and returns a backup encryption key.
func useTempHome(t *testing.T) []byte {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, CONFIG_FOLDER_NAME), 0o700); err != nil {
		t.Fatalf("create config folder: %v", err)
	}
	return []byte("0123456789abcdef0123456789abcdef")
}

// A raw fetch of /app and an expanded fetch of /app_raw are different folders; neither backup may
// overwrite the other, or an offline run serves secrets from the wrong folder.
func TestBackupSecretsRawFolderDoesNotCollideWithSuffixedFolder(t *testing.T) {
	key := useTempHome(t)

	rawApp := []models.SingleEnvironmentVariable{{Key: "FROM", Value: "raw /app"}}
	expandedAppRaw := []models.SingleEnvironmentVariable{{Key: "FROM", Value: "expanded /app_raw"}}

	if err := WriteBackupSecrets("ws", "dev", "/app", false, key, rawApp); err != nil {
		t.Fatalf("write raw /app backup: %v", err)
	}
	if err := WriteBackupSecrets("ws", "dev", "/app_raw", true, key, expandedAppRaw); err != nil {
		t.Fatalf("write expanded /app_raw backup: %v", err)
	}

	for _, tc := range []struct {
		path     string
		expanded bool
		want     string
	}{{"/app", false, "raw /app"}, {"/app_raw", true, "expanded /app_raw"}} {
		got, err := ReadBackupSecrets("ws", "dev", tc.path, tc.expanded, key)
		if err != nil {
			t.Fatalf("read %s (expanded=%v): %v", tc.path, tc.expanded, err)
		}
		if len(got) != 1 || got[0].Value != tc.want {
			t.Errorf("backup %s (expanded=%v) = %+v, want %q", tc.path, tc.expanded, got, tc.want)
		}
	}
}

// Backups written before the expansion mode was part of the name were always expanded; they must
// still be found by an expanded read after upgrading.
func TestBackupSecretsExpandedNameIsUnchanged(t *testing.T) {
	if got, want := backupSecretsFileName("ws", "dev", "/app", true), "project_secrets_ws_dev_-app.json"; got != want {
		t.Errorf("expanded backup name = %q, want the pre-existing %q", got, want)
	}
	if got := backupSecretsFileName("ws", "dev", "/app", false); got == backupSecretsFileName("ws", "dev", "/app", true) {
		t.Errorf("raw and expanded backups share the name %q", got)
	}
}
