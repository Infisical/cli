package itui

import (
	"regexp"
	"strings"

	"github.com/atotto/clipboard"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// StripANSI removes ANSI escape codes from a string
func StripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// CleanForClipboard strips ANSI codes, trims whitespace, and removes
// common terminal prompt prefixes for clean pasting into Slack/Jira.
func CleanForClipboard(s string) string {
	s = StripANSI(s)
	// Strip leading prompt patterns like "$ " or "> "
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "$ ") {
			line = strings.TrimPrefix(line, "$ ")
		} else if strings.HasPrefix(line, "> ") {
			line = strings.TrimPrefix(line, "> ")
		}
		lines[i] = line
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// CopyToClipboard copies cleaned text (ANSI stripped) to system clipboard.
// Returns nil on success, error if clipboard is unavailable.
func CopyToClipboard(text string) error {
	return clipboard.WriteAll(CleanForClipboard(text))
}

// CopyRawToClipboard copies text exactly as-is to system clipboard.
// Use for secret values that must be preserved verbatim.
func CopyRawToClipboard(text string) error {
	return clipboard.WriteAll(text)
}

// CopyAsOneLiner joins multi-line text into a single line for easy pasting.
func CopyAsOneLiner(text string) error {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.TrimSuffix(line, "\\")
		line = strings.TrimSpace(line)
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}
	return clipboard.WriteAll(strings.Join(cleaned, " "))
}

// ReadFromClipboard reads text from the system clipboard.
func ReadFromClipboard() (string, error) {
	return clipboard.ReadAll()
}
