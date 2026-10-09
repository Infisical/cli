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
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, CONFIG_FOLDER_NAME), 0o700); err != nil {
		t.Fatalf("create config folder: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")

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
