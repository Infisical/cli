package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestCompletionCommandIsDiscoverable ensures the built-in `completion` command
// is listed in `--help` output rather than hidden, since the underlying
// generator works correctly but was previously undiscoverable.
func TestCompletionCommandIsDiscoverable(t *testing.T) {
	RootCmd.InitDefaultCompletionCmd()

	cmd, _, err := RootCmd.Find([]string{"completion"})
	if err != nil {
		t.Fatalf("expected to find a 'completion' subcommand, got error: %v", err)
	}
	if cmd.Hidden {
		t.Errorf("expected 'completion' command to be visible, but it is hidden")
	}

	t.Cleanup(func() {
		RootCmd.SetOut(nil)
		RootCmd.SetArgs(nil)
	})

	var out bytes.Buffer
	RootCmd.SetOut(&out)
	RootCmd.SetArgs([]string{"--help"})
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error running --help: %v", err)
	}

	if !strings.Contains(out.String(), "completion") {
		t.Errorf("expected 'completion' to appear in --help output, got:\n%s", out.String())
	}
}

// TestCompletionGeneratesForAllShells verifies each supported shell produces
// a non-empty completion script without error.
func TestCompletionGeneratesForAllShells(t *testing.T) {
	generators := map[string]func(*bytes.Buffer) error{
		"bash":       func(buf *bytes.Buffer) error { return RootCmd.GenBashCompletionV2(buf, true) },
		"zsh":        func(buf *bytes.Buffer) error { return RootCmd.GenZshCompletion(buf) },
		"fish":       func(buf *bytes.Buffer) error { return RootCmd.GenFishCompletion(buf, true) },
		"powershell": func(buf *bytes.Buffer) error { return RootCmd.GenPowerShellCompletionWithDesc(buf) },
	}

	for shell, generate := range generators {
		t.Run(shell, func(t *testing.T) {
			var out bytes.Buffer
			if err := generate(&out); err != nil {
				t.Fatalf("expected no error generating %s completion, got: %v", shell, err)
			}
			if out.Len() == 0 {
				t.Errorf("expected non-empty %s completion script", shell)
			}
		})
	}
}
