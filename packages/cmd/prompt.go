package cmd

import (
	"os"

	"github.com/muesli/ansi"
	"github.com/muesli/reflow/truncate"
	"golang.org/x/term"
)

const (
	// promptui's default select label adds "? " before the label and ": " after
	// it. Keep one extra column free because a trailing space at the last
	// terminal column can still wrap on some terminals.
	selectPromptDecorationWidth = 5
	selectPromptEllipsis        = "…"
)

var getPromptTerminalWidth = func() (int, error) {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	return width, err
}

// promptLabel keeps promptui select labels on one terminal row. promptui's
// screen buffer counts each write as one row, while the terminal may wrap a
// longer write onto multiple rows, which leaves stale rows during redraws.
func promptLabel(label string) string {
	width, err := getPromptTerminalWidth()
	if err != nil {
		return label
	}
	if width <= selectPromptDecorationWidth {
		return ""
	}

	return truncateSelectLabel(label, width-selectPromptDecorationWidth)
}

func truncateSelectLabel(label string, maxWidth int) string {
	if maxWidth <= 0 || ansi.PrintableRuneWidth(label) <= maxWidth {
		return label
	}
	return truncate.StringWithTail(label, uint(maxWidth), selectPromptEllipsis)
}
