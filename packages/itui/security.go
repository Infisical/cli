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
// It verifies the command uses an allowed infisical subcommand and checks
// for shell injection in the command structure (not inside KEY=VALUE values,
// since secret values may legitimately contain special characters).
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

	// First pass: check for newlines and carriage returns in the raw command.
	// These are always dangerous regardless of where they appear.
	for _, ch := range []string{"\n", "\r"} {
		if strings.Contains(command, ch) {
			return fmt.Errorf("command rejected: contains dangerous pattern %q — possible shell injection", ch)
		}
	}

	// Parse tokens for validation
	tokens := strings.Fields(stripped)
	if len(tokens) == 0 {
		return fmt.Errorf("empty command after parsing")
	}

	// Check for shell metacharacters in each token.
	// For KEY=VALUE args (not flags), we only check the KEY portion,
	// because secret values can legitimately contain >, <, $, |, etc.
	// BUT: we also need to detect injection APPENDED to a value like "KEY=val; rm".
	// Strategy: if a token contains = and is not a flag, split on first = and
	// only validate the key. The value part is trusted (came from local cache).
	for _, token := range tokens {
		isKVArg := false
		if eqIdx := strings.Index(token, "="); eqIdx > 0 && !strings.HasPrefix(token, "--") {
			isKVArg = true
			// Check only the key part for dangerous patterns
			keyPart := token[:eqIdx]
			for _, pattern := range dangerousPatterns {
				if strings.Contains(keyPart, pattern) {
					return fmt.Errorf("command rejected: contains dangerous pattern %q — possible shell injection", pattern)
				}
			}
		}

		if !isKVArg {
			// This is a subcommand, flag, or standalone token — check fully
			for _, pattern := range dangerousPatterns {
				if strings.Contains(token, pattern) {
					return fmt.Errorf("command rejected: contains dangerous pattern %q — possible shell injection", pattern)
				}
			}
		}
	}

	// Check two-token subcommands first (e.g., "secrets get")
	if len(tokens) >= 2 {
		twoToken := tokens[0] + " " + tokens[1]
		// For "secrets set", the second token might be KEY=VALUE, so also check
		// just the first word of the second token
		secondWord := tokens[1]
		if eqIdx := strings.Index(secondWord, "="); eqIdx > 0 {
			secondWord = secondWord[:eqIdx]
		}
		twoTokenClean := tokens[0] + " " + secondWord
		if allowedCommands[twoToken] || allowedCommands[twoTokenClean] {
			return nil
		}
	}

	// Check single-token subcommands (e.g., "export")
	if allowedCommands[tokens[0]] {
		return nil
	}

	return fmt.Errorf("command rejected: %q is not an allowed subcommand. Allowed: secrets, export, run, scan, user, login", tokens[0])
}
