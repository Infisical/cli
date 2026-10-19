package util

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupMigrationNoticeTest points the home dir at a temp dir so the notice cache is isolated.
func setupMigrationNoticeTest(t *testing.T) {
	t.Helper()
	isolateHomeDir(t)
	t.Setenv("INFISICAL_DISABLE_MIGRATION_NOTICES", "")
}

func TestDisplayMigrationNotice(t *testing.T) {
	t.Run("prints the title, message and docs link", func(t *testing.T) {
		setupMigrationNoticeTest(t)

		var buf bytes.Buffer
		DisplayMigrationNoticeWithWriter(MigrationNotice{
			ID:      "test-notice",
			Title:   "Important: X is deprecated.",
			Message: "What's happening: X goes away.\nWhat to do: use Y.",
			DocsURL: "https://infisical.com/docs/x-to-y",
		}, &buf)

		want := "Important: X is deprecated.\n" +
			"What's happening: X goes away.\nWhat to do: use Y.\n" +
			"Migration steps: https://infisical.com/docs/x-to-y\n\n"
		if buf.String() != want {
			t.Errorf("notice = %q, want %q", buf.String(), want)
		}
		if !fileExists(migrationNoticeCachePathForTest(t)) {
			t.Error("expected the notice cache file to be written")
		}
	})

	t.Run("omits the docs line without a docs link", func(t *testing.T) {
		setupMigrationNoticeTest(t)

		var buf bytes.Buffer
		DisplayMigrationNoticeWithWriter(MigrationNotice{ID: "test-notice", Title: "Important: X is deprecated.", Message: "What to do: use Y."}, &buf)

		if strings.Contains(buf.String(), "Migration steps:") {
			t.Errorf("expected no docs line, got:\n%s", buf.String())
		}
	})

	t.Run("shown once per day per notice ID", func(t *testing.T) {
		setupMigrationNoticeTest(t)
		notice := MigrationNotice{ID: "first", Title: "first notice", Message: "first"}

		var buf bytes.Buffer
		DisplayMigrationNoticeWithWriter(notice, &buf)
		if buf.Len() == 0 {
			t.Fatal("expected the notice on the first call")
		}

		buf.Reset()
		DisplayMigrationNoticeWithWriter(notice, &buf)
		if buf.Len() != 0 {
			t.Errorf("expected no notice within the TTL, got:\n%s", buf.String())
		}

		buf.Reset()
		DisplayMigrationNoticeWithWriter(MigrationNotice{ID: "second", Title: "second notice", Message: "second"}, &buf)
		if !strings.Contains(buf.String(), "second notice") {
			t.Errorf("a different notice ID should not be throttled, got:\n%s", buf.String())
		}

		cache := readMigrationNoticeCache()
		if _, ok := cache.LastShownTimes["first"]; !ok {
			t.Error("recording the second notice should keep the first one's entry")
		}
	})

	t.Run("keeps both notices in the same cache map", func(t *testing.T) {
		setupMigrationNoticeTest(t)

		var buf bytes.Buffer
		DisplayMigrationNoticeWithWriter(MigrationNotice{ID: "first", Title: "first notice", Message: "first"}, &buf)
		DisplayMigrationNoticeWithWriter(MigrationNotice{ID: "second", Title: "second notice", Message: "second"}, &buf)

		cache := readMigrationNoticeCache()
		if _, ok := cache.LastShownTimes["first"]; !ok {
			t.Error("expected the first notice in the cache map")
		}
		if _, ok := cache.LastShownTimes["second"]; !ok {
			t.Error("expected the second notice in the cache map")
		}
		if len(cache.LastShownTimes) != 2 {
			t.Errorf("cache map length = %d, want 2", len(cache.LastShownTimes))
		}
	})

	t.Run("shown again after the TTL", func(t *testing.T) {
		setupMigrationNoticeTest(t)

		cachePath := migrationNoticeCachePathForTest(t)
		if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		data, err := json.Marshal(migrationNoticeCache{LastShownTimes: map[string]time.Time{"test-notice": time.Now().Add(-25 * time.Hour)}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		writeTestFile(t, cachePath, string(data))

		var buf bytes.Buffer
		DisplayMigrationNoticeWithWriter(MigrationNotice{ID: "test-notice", Title: "Important: X is deprecated.", Message: "use Y"}, &buf)
		if !strings.Contains(buf.String(), "Important:") {
			t.Errorf("expected the notice after the TTL expired, got:\n%s", buf.String())
		}
	})

	t.Run("a corrupt cache doesn't block the notice", func(t *testing.T) {
		setupMigrationNoticeTest(t)

		cachePath := migrationNoticeCachePathForTest(t)
		if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		writeTestFile(t, cachePath, "{not json")

		var buf bytes.Buffer
		DisplayMigrationNoticeWithWriter(MigrationNotice{ID: "test-notice", Title: "Important: X is deprecated.", Message: "use Y"}, &buf)
		if buf.Len() == 0 {
			t.Error("expected the notice when the cache can't be parsed")
		}
		if !migrationNoticeRecentlyShown("test-notice") {
			t.Error("expected the cache to be rewritten after showing the notice")
		}
	})

	t.Run("disabled by INFISICAL_DISABLE_MIGRATION_NOTICES", func(t *testing.T) {
		setupMigrationNoticeTest(t)
		t.Setenv("INFISICAL_DISABLE_MIGRATION_NOTICES", "1")

		var buf bytes.Buffer
		DisplayMigrationNoticeWithWriter(MigrationNotice{ID: "test-notice", Title: "Important: X is deprecated.", Message: "use Y"}, &buf)
		if buf.Len() != 0 {
			t.Errorf("expected no notice, got:\n%s", buf.String())
		}
		if fileExists(migrationNoticeCachePathForTest(t)) {
			t.Error("expected no notice cache file to be written")
		}
	})
}
