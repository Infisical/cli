package util

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

func init() {
	// Disable color output in tests so we can assert on plain text.
	color.NoColor = true
}

func TestIsCacheFresh(t *testing.T) {
	tests := []struct {
		name     string
		cache    *UpdateCheckCache
		expected bool
	}{
		{
			name:     "nil cache needs updating",
			cache:    nil,
			expected: false,
		},
		{
			name: "blank LatestVersion needs updating",
			cache: &UpdateCheckCache{
				LastCheckTime:         time.Now(),
				LatestVersion:         "",
				CurrentVersionAtCheck: CLI_VERSION,
			},
			expected: false,
		},
		{
			name: "mismatched CurrentVersionAtCheck needs updating",
			cache: &UpdateCheckCache{
				LastCheckTime:         time.Now(),
				LatestVersion:         "1.0.0",
				CurrentVersionAtCheck: "old-version",
			},
			expected: false,
		},
		{
			name: "urgent bypasses TTL and needs updating",
			cache: &UpdateCheckCache{
				LastCheckTime:         time.Now(),
				LatestVersion:         "2.0.0",
				CurrentVersionAtCheck: CLI_VERSION,
				IsUrgent:              true,
			},
			expected: false,
		},
		{
			name: "expired TTL (>24h) needs updating",
			cache: &UpdateCheckCache{
				LastCheckTime:         time.Now().Add(-25 * time.Hour),
				LatestVersion:         "2.0.0",
				CurrentVersionAtCheck: CLI_VERSION,
			},
			expected: false,
		},
		{
			name: "fresh cache does not need updating",
			cache: &UpdateCheckCache{
				LastCheckTime:         time.Now().Add(-1 * time.Hour),
				LatestVersion:         "2.0.0",
				CurrentVersionAtCheck: CLI_VERSION,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCacheFresh(tt.cache); got != tt.expected {
				t.Errorf("isCacheFresh() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestDisplayCachedUpdateNotice(t *testing.T) {
	tests := []struct {
		name           string
		cache          *UpdateCheckCache
		expectOutput   bool
		expectContains []string
	}{
		{
			name:         "nil cache produces no output",
			cache:        nil,
			expectOutput: false,
		},
		{
			name: "blank LatestVersion produces no output",
			cache: &UpdateCheckCache{
				LatestVersion:         "",
				CurrentVersionAtCheck: CLI_VERSION,
			},
			expectOutput: false,
		},
		{
			name: "same version produces no output",
			cache: &UpdateCheckCache{
				LatestVersion:         CLI_VERSION,
				CurrentVersionAtCheck: CLI_VERSION,
			},
			expectOutput: false,
		},
		{
			name: "stale cache after upgrade produces no output",
			cache: &UpdateCheckCache{
				LatestVersion:         "2.0.0",
				CurrentVersionAtCheck: "old-version-that-doesnt-match",
			},
			expectOutput: false,
		},
		{
			name: "current version <48h old produces no output",
			cache: &UpdateCheckCache{
				LatestVersion:             "2.0.0",
				CurrentVersionAtCheck:     CLI_VERSION,
				CurrentVersionPublishedAt: time.Now().Add(-24 * time.Hour),
			},
			expectOutput: false,
		},
		{
			name: "urgent ignores 48h grace period",
			cache: &UpdateCheckCache{
				LatestVersion:             "2.0.0",
				CurrentVersionAtCheck:     CLI_VERSION,
				CurrentVersionPublishedAt: time.Now().Add(-24 * time.Hour),
				IsUrgent:                  true,
			},
			expectOutput:   true,
			expectContains: []string{"2.0.0"},
		},
		{
			name: "shows banner when current version >48h old",
			cache: &UpdateCheckCache{
				LatestVersion:             "2.0.0",
				CurrentVersionAtCheck:     CLI_VERSION,
				CurrentVersionPublishedAt: time.Now().Add(-72 * time.Hour),
			},
			expectOutput:   true,
			expectContains: []string{"A new release of infisical is available", CLI_VERSION, "2.0.0"},
		},
		{
			name: "zero publish date shows banner (cannot enforce 48h grace)",
			cache: &UpdateCheckCache{
				LatestVersion:         "2.0.0",
				CurrentVersionAtCheck: CLI_VERSION,
			},
			expectOutput:   true,
			expectContains: []string{"2.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			displayCachedUpdateNotice(&buf, tt.cache)

			if tt.expectOutput && buf.Len() == 0 {
				t.Error("expected output but got none")
			}
			if !tt.expectOutput && buf.Len() != 0 {
				t.Errorf("expected no output, got: %s", buf.String())
			}
			for _, s := range tt.expectContains {
				if !strings.Contains(buf.String(), s) {
					t.Errorf("expected output to contain %q, got: %s", s, buf.String())
				}
			}
		})
	}
}

func TestWriteAndReadUpdateCheckCache(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, UPDATE_CHECK_CACHE_FILE_NAME)

	original := &UpdateCheckCache{
		LastCheckTime:             time.Now().Truncate(time.Second),
		LatestVersion:             "2.0.0",
		LatestVersionPublishedAt:  time.Now().Add(-1 * time.Hour).Truncate(time.Second),
		CurrentVersionPublishedAt: time.Now().Add(-48 * time.Hour).Truncate(time.Second),
		IsUrgent:                  false,
		CurrentVersionAtCheck:     "1.0.0",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}

	readData, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("failed to read cache file: %v", err)
	}

	var loaded UpdateCheckCache
	if err := json.Unmarshal(readData, &loaded); err != nil {
		t.Fatalf("failed to unmarshal cache: %v", err)
	}

	if loaded.LatestVersion != original.LatestVersion {
		t.Errorf("LatestVersion: got %s, want %s", loaded.LatestVersion, original.LatestVersion)
	}
	if loaded.CurrentVersionAtCheck != original.CurrentVersionAtCheck {
		t.Errorf("CurrentVersionAtCheck: got %s, want %s", loaded.CurrentVersionAtCheck, original.CurrentVersionAtCheck)
	}
	if loaded.IsUrgent != original.IsUrgent {
		t.Errorf("IsUrgent: got %v, want %v", loaded.IsUrgent, original.IsUrgent)
	}
	if !loaded.LastCheckTime.Equal(original.LastCheckTime) {
		t.Errorf("LastCheckTime: got %v, want %v", loaded.LastCheckTime, original.LastCheckTime)
	}
}

func TestReadUpdateCheckCache_CorruptJSON(t *testing.T) {
	var cache UpdateCheckCache
	err := json.Unmarshal([]byte(`{not valid json!!!`), &cache)
	if err == nil {
		t.Error("expected error for corrupt JSON")
	}
}

func TestWriteUpdateCheckCache_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "update-check.json")

	cache := &UpdateCheckCache{
		LastCheckTime:         time.Now().Truncate(time.Second),
		LatestVersion:         "3.0.0",
		CurrentVersionAtCheck: "2.0.0",
	}

	data, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Simulate the atomic write pattern.
	tmpFile, err := os.CreateTemp(tmpDir, "update-check-*.json.tmp")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	if err := os.Chmod(tmpFile.Name(), 0600); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}

	if err := os.Rename(tmpFile.Name(), cachePath); err != nil {
		t.Fatalf("failed to rename: %v", err)
	}

	readData, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("failed to read final file: %v", err)
	}

	var loaded UpdateCheckCache
	if err := json.Unmarshal(readData, &loaded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if loaded.LatestVersion != "3.0.0" {
		t.Errorf("got %s, want 3.0.0", loaded.LatestVersion)
	}

	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("got permissions %o, want 0600", perm)
	}
}
