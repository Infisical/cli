package cmd

import "testing"

func TestTruncateSelectLabel(t *testing.T) {
	tests := []struct {
		name     string
		label    string
		maxWidth int
		expected string
	}{
		{name: "fits", label: "Select a project", maxWidth: 17, expected: "Select a project"},
		{name: "truncates", label: "Select a project", maxWidth: 10, expected: "Select a …"},
		{name: "handles unicode width", label: "选择一个项目", maxWidth: 8, expected: "选择一…"},
		{name: "zero width leaves label unchanged", label: "Select a project", maxWidth: 0, expected: "Select a project"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateSelectLabel(tt.label, tt.maxWidth); got != tt.expected {
				t.Fatalf("truncateSelectLabel(%q, %d) = %q, want %q", tt.label, tt.maxWidth, got, tt.expected)
			}
		})
	}
}
