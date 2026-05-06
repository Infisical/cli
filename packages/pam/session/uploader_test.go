package session

import (
	"os"
	"testing"
)

func TestWriteReadPersistedOffset_RoundTrip(t *testing.T) {
	setupTestDir(t)

	filename := "pam_session_abc_ssh_expires_9999999999.enc"
	if err := writePersistedOffset(filename, 12345, 45000); err != nil {
		t.Fatalf("write: %v", err)
	}

	offset, elapsed, ok := readPersistedOffset(filename)
	if !ok {
		t.Fatal("readPersistedOffset returned !ok")
	}
	if offset != 12345 {
		t.Errorf("offset: got %d, want 12345", offset)
	}
	if elapsed != 45000 {
		t.Errorf("lastEndElapsedMs: got %d, want 45000", elapsed)
	}
}

func TestReadPersistedOffset_BackwardCompat(t *testing.T) {
	setupTestDir(t)

	filename := "pam_session_legacy_ssh_expires_9999999999.enc"
	// Old format: just the offset integer, no second line
	path := offsetFilePath(filename)
	if err := os.WriteFile(path, []byte("6789"), 0o600); err != nil {
		t.Fatal(err)
	}

	offset, elapsed, ok := readPersistedOffset(filename)
	if !ok {
		t.Fatal("readPersistedOffset returned !ok")
	}
	if offset != 6789 {
		t.Errorf("offset: got %d, want 6789", offset)
	}
	if elapsed != 0 {
		t.Errorf("lastEndElapsedMs should default to 0 for old format, got %d", elapsed)
	}
}

func TestReadPersistedOffset_Missing(t *testing.T) {
	setupTestDir(t)

	_, _, ok := readPersistedOffset("does-not-exist.enc")
	if ok {
		t.Error("expected !ok for missing file")
	}
}

func TestReadPersistedOffset_Corrupt(t *testing.T) {
	setupTestDir(t)
	filename := "pam_session_bad_ssh_expires_9999999999.enc"
	path := offsetFilePath(filename)
	if err := os.WriteFile(path, []byte("not-a-number"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, ok := readPersistedOffset(filename)
	if ok {
		t.Error("expected !ok for corrupt offset file")
	}
}

func TestDeletePersistedOffset(t *testing.T) {
	setupTestDir(t)
	filename := "pam_session_del_ssh_expires_9999999999.enc"
	if err := writePersistedOffset(filename, 100, 200); err != nil {
		t.Fatal(err)
	}

	path := offsetFilePath(filename)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("offset file should exist: %v", err)
	}

	deletePersistedOffset(filename)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("offset file should have been deleted")
	}
}

func TestParseSessionFilename_NewFormat(t *testing.T) {
	tests := []struct {
		name         string
		filename     string
		wantID       string
		wantType     string
		wantErr      bool
	}{
		{
			name:     "ssh session",
			filename: "pam_session_abc123_ssh_expires_1700000000.enc",
			wantID:   "abc123",
			wantType: ResourceTypeSSH,
		},
		{
			name:     "postgres session",
			filename: "pam_session_def456_postgres_expires_1700000000.enc",
			wantID:   "def456",
			wantType: ResourceTypePostgres,
		},
		{
			name:     "kubernetes session",
			filename: "pam_session_k8s-id_kubernetes_expires_1700000000.enc",
			wantID:   "k8s-id",
			wantType: ResourceTypeKubernetes,
		},
		{
			name:     "uuid session id",
			filename: "pam_session_550e8400-e29b-41d4-a716-446655440000_redis_expires_1700000000.enc",
			wantID:   "550e8400-e29b-41d4-a716-446655440000",
			wantType: ResourceTypeRedis,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseSessionFilename(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if info.SessionID != tt.wantID {
				t.Errorf("sessionID: got %q, want %q", info.SessionID, tt.wantID)
			}
			if info.ResourceType != tt.wantType {
				t.Errorf("resourceType: got %q, want %q", info.ResourceType, tt.wantType)
			}
			if info.Filename != tt.filename {
				t.Errorf("filename: got %q, want %q", info.Filename, tt.filename)
			}
		})
	}
}

func TestParseSessionFilename_LegacyFormat(t *testing.T) {
	info, err := ParseSessionFilename("pam_session_old-id_expires_1700000000.enc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SessionID != "old-id" {
		t.Errorf("sessionID: got %q, want %q", info.SessionID, "old-id")
	}
	if info.ResourceType != "" {
		t.Errorf("legacy should have empty resourceType, got %q", info.ResourceType)
	}
}

func TestParseSessionFilename_Invalid(t *testing.T) {
	invalids := []string{
		"random_file.txt",
		"pam_session_.enc",
		"pam_session_id_expires_notanumber.enc",
		".offset",
	}
	for _, f := range invalids {
		t.Run(f, func(t *testing.T) {
			if _, err := ParseSessionFilename(f); err == nil {
				t.Errorf("expected error for %q", f)
			}
		})
	}
}
