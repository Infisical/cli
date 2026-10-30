package cmd

import (
	"errors"
	"testing"

	"github.com/muesli/ansi"
)

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

func TestPromptLabelUsesTerminalWidth(t *testing.T) {
	originalWidthLookup := getPromptTerminalWidth
	t.Cleanup(func() { getPromptTerminalWidth = originalWidthLookup })

	tests := []struct {
		name       string
		width      int
		widthErr   error
		label      string
		want       string
		maxDisplay int
	}{
		{
			name:       "reserves prompt decoration and safety column",
			width:      15,
			label:      "A label that is too wide",
			want:       "A label t…",
			maxDisplay: 10,
		},
		{
			name:       "handles one-column label budget",
			width:      6,
			label:      "wide label",
			want:       "…",
			maxDisplay: 1,
		},
		{
			name:  "hides label on an unusably narrow terminal",
			width: 5,
			label: "wide label",
			want:  "",
		},
		{
			name:       "keeps label when terminal width lookup fails",
			widthErr:   errors.New("not a terminal"),
			label:      "wide label",
			want:       "wide label",
			maxDisplay: ansi.PrintableRuneWidth("wide label"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getPromptTerminalWidth = func() (int, error) { return tt.width, tt.widthErr }

			got := promptLabel(tt.label)
			if got != tt.want {
				t.Fatalf("promptLabel(%q) = %q, want %q", tt.label, got, tt.want)
			}
			if tt.maxDisplay > 0 && ansi.PrintableRuneWidth(got) > tt.maxDisplay {
				t.Fatalf("promptLabel(%q) display width = %d, want <= %d", tt.label, ansi.PrintableRuneWidth(got), tt.maxDisplay)
			}
		})
	}
}
