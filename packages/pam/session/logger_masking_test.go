package session

import (
	"regexp"
	"testing"
)

func TestApplyMasking(t *testing.T) {
	logger := &EncryptedSessionLogger{
		maskingPatterns: []*regexp.Regexp{
			regexp.MustCompile(`password\s*=\s*\S+`),
			regexp.MustCompile(`secret_key`),
		},
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
