package session

import (
	"bytes"
	"encoding/base64"
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

func TestSessionLoggerMasksCommandThatNeedsItsPrompt(t *testing.T) {
	setupTestDir(t)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	expiresAt := time.Now().Add(time.Hour)
	masker := masking.New([]*regexp.Regexp{regexp.MustCompile(`Token:\s*\S+`)}, false, nil, "sess-prompt")

	logger, err := NewSessionLogger("sess-prompt", key, expiresAt, "ssh", masker)
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}
	if err := logger.LogSessionEvent(SessionEvent{
		Timestamp:   time.Now(),
		EventType:   SessionEventOutput,
		ChannelType: SessionChannelShell,
		Data:        []byte("Token: abc123"),
		Command:     "abc123",
	}); err != nil {
		t.Fatalf("LogSessionEvent: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	filename := fmt.Sprintf("pam_session_sess-prompt_ssh_expires_%d.enc", expiresAt.Unix())
	payload, _, _, _, err := readFromOffset(filename, key, 0, 1<<20)
	if err != nil {
		t.Fatalf("readFromOffset: %v", err)
	}
	if strings.Contains(string(payload), "abc123") {
		t.Errorf("recording kept a secret its prompt masks: %s", payload)
	}
	if !strings.Contains(string(payload), `"command":"[MASKED]"`) {
		t.Errorf("recording lost the masked command: %s", payload)
	}
}

func TestSessionLoggerMasksCommandThatOnlyMatchesAlone(t *testing.T) {
	setupTestDir(t)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	expiresAt := time.Now().Add(time.Hour)
	masker := masking.New([]*regexp.Regexp{regexp.MustCompile(`^mysql -p\S+`)}, false, nil, "sess-anchored")

	logger, err := NewSessionLogger("sess-anchored", key, expiresAt, "ssh", masker)
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}
	if err := logger.LogSessionEvent(SessionEvent{
		Timestamp:   time.Now(),
		EventType:   SessionEventOutput,
		ChannelType: SessionChannelShell,
		Data:        []byte("$ mysql -pS3cret"),
		Command:     "mysql -pS3cret",
	}); err != nil {
		t.Fatalf("LogSessionEvent: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	filename := fmt.Sprintf("pam_session_sess-anchored_ssh_expires_%d.enc", expiresAt.Unix())
	payload, _, _, _, err := readFromOffset(filename, key, 0, 1<<20)
	if err != nil {
		t.Fatalf("readFromOffset: %v", err)
	}
	if !strings.Contains(string(payload), `"command":"[MASKED]"`) {
		t.Errorf("command lost the masking its own pattern applies: %s", payload)
	}
}
