package itui

import (
	"fmt"
	"strings"
)

// allowedCommands is the allowlist of infisical subcommands that ITUI can execute
var allowedCommands = map[string]bool{
	"secrets":         true,
	"secrets get":     true,
	"secrets set":     true,
	"secrets delete":  true,
	"secrets folders": true,
	"export":          true,
	"run":             true,
	"scan":            true,
	"user":            true,
	"login":           true,
}

// dangerousPatterns are shell metacharacters that indicate injection attempts
var dangerousPatterns = []string{
	";",
	"|",
	"&&",
	"||",
	"`",
	"$(",
	"${",
	">",
	"<",
	"\n",
	"\r",
}

// ValidateCommand checks that an AI-generated command is safe to execute.
// It verifies the command uses an allowed infisical subcommand and contains
// no shell injection patterns.
func ValidateCommand(command string) error {
	command = strings.TrimSpace(command)

	if command == "" {
		return fmt.Errorf("empty command")
	}

	// Strip "infisical " prefix if present
	stripped := command
	if strings.HasPrefix(stripped, "infisical ") {
		stripped = strings.TrimPrefix(stripped, "infisical ")
	}

	// Check for shell metacharacters in the full command
	for _, pattern := range dangerousPatterns {
		if strings.Contains(command, pattern) {
			return fmt.Errorf("command rejected: contains dangerous pattern %q — possible shell injection", pattern)
		}
	}

	// Parse the subcommand (first 1-2 tokens)
	tokens := strings.Fields(stripped)
	if len(tokens) == 0 {
		return fmt.Errorf("empty command after parsing")
	}

	// Check two-token subcommands first (e.g., "secrets get")
	if len(tokens) >= 2 {
		twoToken := tokens[0] + " " + tokens[1]
		if allowedCommands[twoToken] {
			return nil
		}
	}

	// Check single-token subcommands (e.g., "export")
	if allowedCommands[tokens[0]] {
		return nil
	}

	return fmt.Errorf("command rejected: %q is not an allowed subcommand. Allowed: secrets, export, run, scan, user, login", tokens[0])
}
