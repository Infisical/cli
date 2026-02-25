package itui

import "testing"

func TestStripANSI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no ANSI codes",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "color codes",
			input:    "\x1b[31mERROR\x1b[0m: something failed",
			expected: "ERROR: something failed",
		},
		{
			name:     "bold and reset",
			input:    "\x1b[1mBold text\x1b[0m normal",
			expected: "Bold text normal",
		},
		{
			name:     "multiple codes",
			input:    "\x1b[32m✓\x1b[0m \x1b[33mwarning\x1b[0m \x1b[31merror\x1b[0m",
			expected: "✓ warning error",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripANSI(tt.input)
			if got != tt.expected {
				t.Errorf("StripANSI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCleanForClipboard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "strips ANSI and trims",
			input:    "  \x1b[32mhello\x1b[0m  ",
			expected: "hello",
		},
		{
			name:     "strips prompt prefix $",
			input:    "$ infisical export --env=dev",
			expected: "infisical export --env=dev",
		},
		{
			name:     "strips prompt prefix >",
			input:    "> some command",
			expected: "some command",
		},
		{
			name:     "multi-line with prompts",
			input:    "$ command one\n$ command two\noutput line",
			expected: "command one\ncommand two\noutput line",
		},
		{
			name:     "preserves normal text",
			input:    "DATABASE_URL=postgres://localhost:5432/db",
			expected: "DATABASE_URL=postgres://localhost:5432/db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanForClipboard(tt.input)
			if got != tt.expected {
				t.Errorf("CleanForClipboard(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
