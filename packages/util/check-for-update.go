package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
)

func CheckForUpdate() {
	CheckForUpdateWithWriter(os.Stderr)
}

func CheckForUpdateWithWriter(w io.Writer) {
	if checkEnv := os.Getenv("INFISICAL_DISABLE_UPDATE_CHECK"); checkEnv != "" {
		return
	}
	latestVersion, publishedAt, isUrgent, err := getLatestTag("Infisical", "cli")
	if err != nil {
		log.Debug().Err(err)
		// do nothing and continue
		return
	}

	// Only prompt if the release is at least 48 hours old, unless it's marked as urgent
	hoursSinceRelease := time.Since(publishedAt).Hours()
	if !isUrgent && hoursSinceRelease < 48 {
		return
	}

	if latestVersion != CLI_VERSION {
		yellow := color.New(color.FgYellow).SprintFunc()
		blue := color.New(color.FgCyan).SprintFunc()
		black := color.New(color.FgBlack).SprintFunc()

		msg := fmt.Sprintf("%s %s %s %s",
			yellow("A new release of infisical is available:"),
			blue(CLI_VERSION),
			black("->"),
			blue(latestVersion),
		)

		fmt.Fprintln(w, msg)

		updateInstructions := GetUpdateInstructions()

		if updateInstructions != "" {
			msg = fmt.Sprintf("\n%s\n", GetUpdateInstructions())
			fmt.Fprintln(w, msg)
		}

	}
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
	resp, err := http.Get(url)
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

	cgroup, err := ioutil.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}

	return strings.Contains(string(cgroup), "docker")
}
