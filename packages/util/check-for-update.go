package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
)

var githubHTTPClient = &http.Client{Timeout: 8 * time.Second}

var updateCheckWg sync.WaitGroup

const updateCheckCacheTTL = 24 * time.Hour

type UpdateCheckCache struct {
	LastCheckTime             time.Time `json:"lastCheckTime"`
	LatestVersion             string    `json:"latestVersion"`
	LatestVersionPublishedAt  time.Time `json:"latestVersionPublishedAt"`
	CurrentVersionPublishedAt time.Time `json:"currentVersionPublishedAt"`
	IsUrgent                  bool      `json:"isUrgent"`
	CurrentVersionAtCheck     string    `json:"currentVersionAtCheck"`
}

func CheckForUpdateWithWriter(w io.Writer) {
	if checkEnv := os.Getenv("INFISICAL_DISABLE_UPDATE_CHECK"); checkEnv != "" {
		return
	}

	cache := readUpdateCheckCache()

	displayCachedUpdateNotice(w, cache)

	if !isCacheFresh(cache) {
		updateCheckWg.Add(1)
		go func() {
			defer updateCheckWg.Done()
			performUpdateCheckInBackground()
		}()
	}
}

// WaitForUpdateCheck blocks until the background update check goroutine completes.
// Call this before program exit to ensure the cache gets written.
func WaitForUpdateCheck() {
	updateCheckWg.Wait()
}

// isCacheFresh returns true if the cache is fresh enough to skip a network check.
func isCacheFresh(cache *UpdateCheckCache) bool {
	if cache == nil || cache.LatestVersion == "" || cache.CurrentVersionAtCheck != CLI_VERSION {
		return false
	}
	if cache.IsUrgent {
		return false
	}
	return time.Since(cache.LastCheckTime) < updateCheckCacheTTL
}

// displayCachedUpdateNotice prints an update notification from cached data.
func displayCachedUpdateNotice(w io.Writer, cache *UpdateCheckCache) {
	if cache == nil || cache.LatestVersion == "" || cache.LatestVersion == CLI_VERSION {
		return
	}
	// Don't show stale notifications after the user has upgraded.
	if cache.CurrentVersionAtCheck != CLI_VERSION {
		return
	}
	// Unless urgent, skip notification if the current version is less than 48h old.
	if !cache.IsUrgent && !cache.CurrentVersionPublishedAt.IsZero() &&
		time.Since(cache.CurrentVersionPublishedAt).Hours() < 48 {
		return
	}

	yellow := color.New(color.FgYellow).SprintFunc()
	blue := color.New(color.FgCyan).SprintFunc()
	black := color.New(color.FgBlack).SprintFunc()

	msg := fmt.Sprintf("%s %s %s %s",
		yellow("A new release of infisical is available:"),
		blue(CLI_VERSION),
		black("->"),
		blue(cache.LatestVersion),
	)

	fmt.Fprintln(w, msg)

	updateInstructions := GetUpdateInstructions()
	if updateInstructions != "" {
		msg = fmt.Sprintf("\n%s\n", updateInstructions)
		fmt.Fprintln(w, msg)
	}
}

// performUpdateCheckInBackground fetches update info from GitHub and writes to cache.
// It is designed to be called as a fire-and-forget goroutine.
func performUpdateCheckInBackground() {
	latestVersion, latestPublishedAt, isUrgent, err := getLatestTag("Infisical", "cli")
	if err != nil {
		log.Debug().Err(err).Msg("background update check: failed to get latest tag")
		return
	}

	cache := &UpdateCheckCache{
		LastCheckTime:            time.Now(),
		LatestVersion:            latestVersion,
		LatestVersionPublishedAt: latestPublishedAt,
		IsUrgent:                 isUrgent,
		CurrentVersionAtCheck:    CLI_VERSION,
	}

	// If versions differ, fetch the publish date for the current version (for 48h grace).
	if latestVersion != CLI_VERSION {
		currentPublishedAt, err := getReleasePublishedAt("Infisical", "cli", CLI_VERSION)
		if err != nil {
			log.Debug().Err(err).Msg("background update check: failed to get current version publish date")
			// Non-fatal — we just won't have the 48h grace period data.
		} else {
			cache.CurrentVersionPublishedAt = currentPublishedAt
		}
	}

	if err := writeUpdateCheckCache(cache); err != nil {
		log.Debug().Err(err).Msg("background update check: failed to write cache")
	}
}

// getUpdateCheckCachePath returns the path to ~/.infisical/update-check.json.
func getUpdateCheckCachePath() (string, error) {
	homeDir, err := GetHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, CONFIG_FOLDER_NAME, UPDATE_CHECK_CACHE_FILE_NAME), nil
}

// readUpdateCheckCache reads and unmarshals the cache file. Returns nil on any error (cache miss).
func readUpdateCheckCache() *UpdateCheckCache {
	path, err := getUpdateCheckCachePath()
	if err != nil {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var cache UpdateCheckCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}

	return &cache
}

// writeUpdateCheckCache atomically writes the cache file using a temp file + rename.
func writeUpdateCheckCache(cache *UpdateCheckCache) error {
	path, err := getUpdateCheckCachePath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	data, err := json.Marshal(cache)
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, "update-check-*.json.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

func DisplayAptInstallationChangeBanner(isSilent bool) {
	DisplayAptInstallationChangeBannerWithWriter(isSilent, os.Stderr)
}

func DisplayAptInstallationChangeBannerWithWriter(isSilent bool, w io.Writer) {
	if isSilent {
		return
	}

	if runtime.GOOS == "linux" {
		_, err := exec.LookPath("apt-get")
		isApt := err == nil
		if isApt {
			yellow := color.New(color.FgYellow).SprintFunc()
			msg := fmt.Sprintf("%s",
				yellow("Update Required: Your current package installation script is outdated and will no longer receive updates.\nPlease update to the new installation script which can be found here https://infisical.com/docs/cli/overview#installation debian section\n"),
			)

			fmt.Fprintln(w, msg)
		}
	}
}

func getLatestTag(repoOwner string, repoName string) (string, time.Time, bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", repoOwner, repoName)
	resp, err := githubHTTPClient.Get(url)
	if err != nil {
		return "", time.Time{}, false, err
	}
	if resp.StatusCode != 200 {
		return "", time.Time{}, false, errors.New(fmt.Sprintf("gitHub API returned status code %d", resp.StatusCode))
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, false, err
	}

	var releaseDetails struct {
		TagName     string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
		Body        string `json:"body"`
	}

	if err := json.Unmarshal(body, &releaseDetails); err != nil {
		return "", time.Time{}, false, fmt.Errorf("failed to unmarshal github response: %w", err)
	}

	publishedAt, err := time.Parse(time.RFC3339, releaseDetails.PublishedAt)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("failed to parse release time: %w", err)
	}

	isUrgent := strings.Contains(releaseDetails.Body, "#urgent")

	tag_prefix := "v"

	// Extract the version from the first valid tag
	version := strings.TrimPrefix(releaseDetails.TagName, tag_prefix)

	return version, publishedAt, isUrgent, nil
}

func getReleasePublishedAt(repoOwner string, repoName string, version string) (time.Time, error) {
	tag := "v" + version
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", repoOwner, repoName, tag)
	resp, err := githubHTTPClient.Get(url)
	if err != nil {
		return time.Time{}, err
	}
	if resp.StatusCode != 200 {
		return time.Time{}, errors.New(fmt.Sprintf("gitHub API returned status code %d", resp.StatusCode))
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, err
	}

	var releaseDetails struct {
		PublishedAt string `json:"published_at"`
	}

	if err := json.Unmarshal(body, &releaseDetails); err != nil {
		return time.Time{}, fmt.Errorf("failed to unmarshal github response: %w", err)
	}

	publishedAt, err := time.Parse(time.RFC3339, releaseDetails.PublishedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse release time: %w", err)
	}

	return publishedAt, nil
}

func GetUpdateInstructions() string {
	os := runtime.GOOS
	switch os {
	case "darwin":
		return "To update, run: brew update && brew upgrade infisical"
	case "windows":
		return "To update, run: scoop update infisical"
	case "linux":
		pkgManager := getLinuxPackageManager()
		switch pkgManager {
		case "apt-get":
			return "To update, run: sudo apt-get update && sudo apt-get install infisical"
		case "yum":
			return "To update, run: sudo yum update infisical"
		case "apk":
			return "To update, run: sudo apk update && sudo apk upgrade infisical"
		case "yay":
			return "To update, run: yay -Syu infisical"
		default:
			return ""
		}
	default:
		return ""
	}
}

func getLinuxPackageManager() string {
	cmd := exec.Command("apt-get", "--version")
	if err := cmd.Run(); err == nil {
		return "apt-get"
	}

	cmd = exec.Command("yum", "--version")
	if err := cmd.Run(); err == nil {
		return "yum"
	}

	cmd = exec.Command("yay", "--version")
	if err := cmd.Run(); err == nil {
		return "yay"
	}

	cmd = exec.Command("apk", "--version")
	if err := cmd.Run(); err == nil {
		return "apk"
	}

	return ""
}

func IsRunningInDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}

	return strings.Contains(string(cgroup), "docker")
}
