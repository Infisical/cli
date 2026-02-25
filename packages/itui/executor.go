package itui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Executor wraps os/exec for running infisical CLI commands
type Executor struct {
	binaryPath string
}

// NewExecutor creates a new Executor that shells out to the infisical binary
func NewExecutor() *Executor {
	path, err := exec.LookPath("infisical")
	if err != nil {
		path = "infisical" // fallback, will fail at runtime with clear error
	}
	return &Executor{binaryPath: path}
}

// Run executes an infisical command with the given arguments
func (e *Executor) Run(args ...string) CommandResult {
	start := time.Now()

	cmd := exec.Command(e.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return CommandResult{
		Command:  e.binaryPath + " " + strings.Join(args, " "),
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Error:    err,
		ExecTime: time.Since(start),
	}
}

// RunRaw executes a raw command string (from AI output).
// It validates the command against the allowlist and checks for shell injection
// before executing.
func (e *Executor) RunRaw(command string) CommandResult {
	// Validate command before execution
	if err := ValidateCommand(command); err != nil {
		return CommandResult{
			Command: command,
			Error:   fmt.Errorf("security: %w", err),
			Stderr:  err.Error(),
		}
	}

	// Strip "infisical " prefix if present
	command = strings.TrimSpace(command)
	if strings.HasPrefix(command, "infisical ") {
		command = strings.TrimPrefix(command, "infisical ")
	}

	// Split into args, respecting quotes
	args := splitArgs(command)
	return e.Run(args...)
}

// RunSecretSet executes a `secrets set` command with properly separated args.
// KEY=VALUE pairs are kept as single arguments to prevent values with spaces
// or special characters from being broken up.
func (e *Executor) RunSecretSet(keyValues []string, flags []string) CommandResult {
	args := []string{"secrets", "set"}
	args = append(args, keyValues...)
	args = append(args, flags...)
	return e.Run(args...)
}

// ParseSetCommand splits a hydrated `secrets set KEY=VALUE --flag=val` command
// into key-value pairs and flags. KEY=VALUE args (where key doesn't start with --)
// are kept intact as single strings.
func ParseSetCommand(command string) (kvPairs []string, flags []string) {
	// Strip "infisical " prefix
	cmd := strings.TrimSpace(command)
	if strings.HasPrefix(cmd, "infisical ") {
		cmd = strings.TrimPrefix(cmd, "infisical ")
	}
	// Strip "secrets set " prefix
	if strings.HasPrefix(cmd, "secrets set ") {
		cmd = strings.TrimPrefix(cmd, "secrets set ")
	} else if strings.HasPrefix(cmd, "secrets set") {
		cmd = strings.TrimPrefix(cmd, "secrets set")
	}
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil, nil
	}

	// Split respecting quotes
	tokens := splitArgs(cmd)
	for _, token := range tokens {
		if strings.HasPrefix(token, "--") || strings.HasPrefix(token, "-") {
			flags = append(flags, token)
		} else if strings.Contains(token, "=") {
			kvPairs = append(kvPairs, token)
		} else {
			// Might be a flag value or part of something, treat as flag
			flags = append(flags, token)
		}
	}
	return kvPairs, flags
}

// IsSecretsSetCommand returns true if the command is an `infisical secrets set` command
func IsSecretsSetCommand(command string) bool {
	cmd := strings.TrimSpace(command)
	if strings.HasPrefix(cmd, "infisical ") {
		cmd = strings.TrimPrefix(cmd, "infisical ")
	}
	return strings.HasPrefix(cmd, "secrets set")
}

// FetchSecrets retrieves secrets for the given environment and path
func (e *Executor) FetchSecrets(env, path string) ([]Secret, error) {
	args := []string{"export", "--format=json", "--env=" + env}
	if path != "" && path != "/" {
		args = append(args, "--path="+path)
	}

	result := e.Run(args...)
	if result.Error != nil {
		errMsg := result.Stderr
		if errMsg == "" {
			errMsg = result.Error.Error()
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	stdout := strings.TrimSpace(result.Stdout)
	if stdout == "" || stdout == "null" {
		return []Secret{}, nil
	}

	var secrets []Secret
	if err := json.Unmarshal([]byte(stdout), &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse secrets JSON: %w\nRaw output: %s", err, stdout)
	}

	return secrets, nil
}

// CheckAuth checks if the user is logged in
func (e *Executor) CheckAuth() (email string, loggedIn bool) {
	result := e.Run("user")
	if result.Error != nil {
		return "", false
	}
	// Parse output for email
	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.Contains(line, "email") || strings.Contains(line, "Email") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), true
			}
		}
	}
	return "", result.Error == nil
}

// splitArgs splits a command string into arguments, respecting quoted strings
func splitArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		} else if c == '\'' || c == '"' {
			inQuote = true
			quoteChar = c
		} else if c == ' ' || c == '\t' {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}
