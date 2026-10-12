package util

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
)

const migrationNoticeCacheTTL = 24 * time.Hour

type MigrationNotice struct {
	ID string
	Title string
	Message string
	DocsURL string
}

type migrationNoticeCache struct {
	LastShownTimes map[string]time.Time `json:"lastShownTimes"`
}

// migrationNoticeCacheSingleton is the one cache map for this process. 
var migrationNoticeCacheSingleton = migrationNoticeCache{LastShownTimes: map[string]time.Time{}}

var migrationNoticeCachePath string

func getMigrationNoticeCachePath() (string, error) {
	homeDir, err := GetHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, CONFIG_FOLDER_NAME, MIGRATION_NOTICE_CACHE_FILE_NAME), nil
}

// readMigrationNoticeCache returns the process-wide cache. The LastShownTimes map is
// allocated once; a later read for the same path returns that map. A different cache
// path clears it and loads that file. A missing or unreadable file leaves the map empty.
func readMigrationNoticeCache() migrationNoticeCache {
	path, err := getMigrationNoticeCachePath()
	if err == nil && path == migrationNoticeCachePath {
		return migrationNoticeCacheSingleton
	}

	clear(migrationNoticeCacheSingleton.LastShownTimes)
	migrationNoticeCachePath = path
	if err != nil {
		return migrationNoticeCacheSingleton
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return migrationNoticeCacheSingleton
	}

	var decoded migrationNoticeCache
	if json.Unmarshal(data, &decoded) != nil || decoded.LastShownTimes == nil {
		return migrationNoticeCacheSingleton
	}
	maps.Copy(migrationNoticeCacheSingleton.LastShownTimes, decoded.LastShownTimes)
	return migrationNoticeCacheSingleton
}

// migrationNoticeRecentlyShown returns true if the notice with this ID was shown within the TTL.
func migrationNoticeRecentlyShown(id string) bool {
	lastShownTime, ok := readMigrationNoticeCache().LastShownTimes[id]
	return ok && time.Since(lastShownTime) < migrationNoticeCacheTTL
}

// recordMigrationNoticeShown stamps the cache so the notice with this ID is throttled.
func recordMigrationNoticeShown(id string) {
	path, err := getMigrationNoticeCachePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return
	}
	cache := readMigrationNoticeCache()
	cache.LastShownTimes[id] = time.Now()
	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	// Best-effort write; a failure just means the notice may show again next run.
	_ = WriteFileAtomic(path, data, 0o600)
}

func DisplayMigrationNoticeWithWriter(notice MigrationNotice, w io.Writer) {
	if os.Getenv("INFISICAL_DISABLE_MIGRATION_NOTICES") != "" {
		return
	}
	if migrationNoticeRecentlyShown(notice.ID) {
		return
	}

	yellow := color.New(color.FgYellow).SprintFunc()
	bold := color.New(color.FgYellow, color.Bold).SprintFunc()

	body := notice.Message
	if notice.DocsURL != "" {
		body += "\nMigration steps: " + notice.DocsURL
	}

	fmt.Fprintln(w, bold(notice.Title))
	fmt.Fprintln(w, yellow(body+"\n"))

	recordMigrationNoticeShown(notice.ID)
}
