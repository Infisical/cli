package cmd

import (
	"strings"
	"testing"
)

func TestZshShellInit(t *testing.T) {
	for _, expected := range []string{
		"if [[ -o interactive ]]; then",
		"_infisical_auto_run_prefixes=(npm pnpm bun node)",
		"BUFFER=\"infisical run -- $BUFFER\"",
		"zle .accept-line",
	} {
		if !strings.Contains(zshShellInit, expected) {
			t.Errorf("shell initialization script does not contain %q", expected)
		}
	}
}
