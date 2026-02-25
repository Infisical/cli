package itui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AuditEntry represents a single auditable action in ITUI
type AuditEntry struct {
	Timestamp        string `json:"timestamp"`
	UserEmail        string `json:"user_email"`
	Environment      string `json:"environment"`
	UserPrompt       string `json:"user_prompt"`
	SanitizedPrompt  string `json:"sanitized_prompt,omitempty"`
	AICommand        string `json:"ai_command,omitempty"`
	HydratedCommand  string `json:"hydrated_command,omitempty"`
	ValidationResult string `json:"validation_result"`
	ExecutionResult  string `json:"execution_result,omitempty"`
	ExecutionError   string `json:"execution_error,omitempty"`
}

// AuditLogger writes append-only JSON audit entries to ~/.itui/audit.log
type AuditLogger struct {
	logPath string
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger() *AuditLogger {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return &AuditLogger{
		logPath: filepath.Join(home, ".itui", "audit.log"),
	}
}

// Log writes an audit entry. Non-blocking: errors are silently ignored
// to avoid disrupting the TUI experience.
func (a *AuditLogger) Log(entry AuditEntry) {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Ensure directory exists
	dir := filepath.Dir(a.logPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}

	f, err := os.OpenFile(a.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	fmt.Fprintf(f, "%s\n", data)
}
