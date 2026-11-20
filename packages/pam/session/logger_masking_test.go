package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session/masking"
)

func TestApplyMasking(t *testing.T) {
	logger := &EncryptedSessionLogger{
		masker: masking.New([]*regexp.Regexp{
			regexp.MustCompile(`password\s*=\s*\S+`),
			regexp.MustCompile(`secret_key`),
		}, false, nil, "sess-1"),
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "masks password pattern",
			input:    "SET password = hunter2",
			expected: "SET [MASKED]",
		},
		{
			name:     "masks secret_key",
			input:    "export secret_key=abc123",
			expected: "export [MASKED]=abc123",
		},
		{
			name:     "masks multiple occurrences",
			input:    "password=foo and password=bar",
			expected: "[MASKED] and [MASKED]",
		},
		{
			name:     "no match leaves input unchanged",
			input:    "SELECT * FROM users",
			expected: "SELECT * FROM users",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := logger.applyMaskingString(tt.input)
			if result != tt.expected {
				t.Errorf("applyMaskingString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}

	// Test byte variant
	t.Run("applyMasking bytes", func(t *testing.T) {
		input := []byte("password = secret123")
		result := logger.applyMasking(input)
		expected := "[MASKED]"
		if string(result) != expected {
			t.Errorf("applyMasking(%q) = %q, want %q", input, result, expected)
		}
	})
}

func TestApplyMaskingNoPatterns(t *testing.T) {
	logger := &EncryptedSessionLogger{}

	input := "password=secret"
	result := logger.applyMaskingString(input)
	if result != input {
		t.Errorf("with no patterns, expected input unchanged, got %q", result)
	}

	byteInput := []byte("password=secret")
	byteResult := logger.applyMasking(byteInput)
	if string(byteResult) != string(byteInput) {
		t.Errorf("with no patterns, expected bytes unchanged")
	}
}

func TestSessionLoggerMasksCommandAndURL(t *testing.T) {
	setupTestDir(t)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	expiresAt := time.Now().Add(time.Hour)
	masker := masking.New([]*regexp.Regexp{regexp.MustCompile(`-p\S+`)}, false, nil, "sess-mask")

	logger, err := NewSessionLogger("sess-mask", key, expiresAt, "ssh", masker)
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}
	if err := logger.LogSessionEvent(SessionEvent{
		Timestamp:   time.Now(),
		EventType:   SessionEventOutput,
		ChannelType: SessionChannelShell,
		Data:        []byte("user@host:~$ mysql -pS3cret"),
		Command:     "mysql -pS3cret",
	}); err != nil {
		t.Fatalf("LogSessionEvent: %v", err)
	}
	if err := logger.LogHttpEvent(HttpEvent{
		Timestamp: time.Now(),
		EventType: HttpEventRequest,
		RequestId: "r1",
		Method:    "GET",
		URL:       "/api/v1/exec?command=-pS3cret",
	}); err != nil {
		t.Fatalf("LogHttpEvent: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	filename := fmt.Sprintf("pam_session_sess-mask_ssh_expires_%d.enc", expiresAt.Unix())
	payload, _, _, _, err := readFromOffset(filename, key, 0, 1<<20)
	if err != nil {
		t.Fatalf("readFromOffset: %v", err)
	}
	if strings.Contains(string(payload), "S3cret") {
		t.Errorf("recording kept a masked secret: %s", payload)
	}
	if !strings.Contains(string(payload), `"command":"mysql [MASKED]"`) {
		t.Errorf("recording lost the masked command: %s", payload)
	}
}

// recordCommand logs one echoed command line with the given masking patterns and returns the command
// the recording keeps.
func recordCommand(t *testing.T, patterns []*regexp.Regexp, line, command string) string {
	t.Helper()
	setupTestDir(t)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	expiresAt := time.Now().Add(time.Hour)

	logger, err := NewSessionLogger("sess-cmd", key, expiresAt, "ssh", masking.New(patterns, false, nil, "sess-cmd"))
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}
	if err := logger.LogSessionEvent(SessionEvent{
		Timestamp:   time.Now(),
		EventType:   SessionEventOutput,
		ChannelType: SessionChannelShell,
		Data:        []byte(line),
		Command:     command,
	}); err != nil {
		t.Fatalf("LogSessionEvent: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	payload, _, _, _, err := readFromOffset(fmt.Sprintf("pam_session_sess-cmd_ssh_expires_%d.enc", expiresAt.Unix()), key, 0, 1<<20)
	if err != nil {
		t.Fatalf("readFromOffset: %v", err)
	}
	var events []SessionEvent
	if err := json.Unmarshal(payload, &events); err != nil || len(events) != 1 {
		t.Fatalf("decoding %s: %v", payload, err)
	}
	return events[0].Command
}

func TestSessionLoggerMasksCommands(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		line     string
		command  string
		want     string
	}{
		{
			name:     "keeps the masked command when the pattern sits inside it",
			patterns: []string{`-p\S+`},
			line:     "user@host:~$ mysql -pS3cret",
			command:  "mysql -pS3cret",
			want:     "mysql [MASKED]",
		},
		{
			name:     "keeps the command when only the prompt is masked",
			patterns: []string{`10\.0\.0\.5`},
			line:     "user@10.0.0.5:~$ ls",
			command:  "ls",
			want:     "ls",
		},
		{
			name:     "masks a command whose pattern needs the prompt",
			patterns: []string{`Token:\s*\S+`},
			line:     "Token: abc123",
			command:  "abc123",
			want:     "[MASKED]",
		},
		{
			name:     "masks a command whose pattern only matches it alone",
			patterns: []string{`^mysql -p\S+`},
			line:     "$ mysql -pS3cret",
			command:  "mysql -pS3cret",
			want:     "[MASKED]",
		},
		{
			name:     "masks a command when masking it alone removes text a later pattern needs",
			patterns: []string{`^password=\S+`, `Credentials: password=\S+ token=\S+`},
			line:     "Credentials: password=first token=second",
			command:  "password=first token=second",
			want:     "[MASKED]",
		},
		{
			name:     "masks a command the line no longer ends with",
			patterns: []string{`Token: [A-Za-z0-9]+`},
			line:     "Token: abc123\u00a0",
			command:  "abc123",
			want:     "[MASKED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := make([]*regexp.Regexp, len(tt.patterns))
			for i, pattern := range tt.patterns {
				patterns[i] = regexp.MustCompile(pattern)
			}
			if got := recordCommand(t, patterns, tt.line, tt.command); got != tt.want {
				t.Errorf("command = %q, want %q", got, tt.want)
			}
		})
	}
}
