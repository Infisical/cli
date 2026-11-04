package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/spf13/cobra"
)

// With structured output, stderr carries only the structured error, so the plain-text warning that a
// token replaces the login session is held back. Text output keeps it.
func TestTokenOverrideWarningRespectsStructuredOutput(t *testing.T) {
	token := &models.TokenDetails{Source: "--token flag"}
	cases := []struct {
		args []string
		warn bool
	}{
		{nil, true},
		{[]string{"-o", "json"}, false},
		{[]string{"--output", "yaml"}, false},
		{[]string{"-o", "JSON"}, false},
		{[]string{"--format", "json"}, false},
		{[]string{"--format", "dotenv"}, true},
	}
	for _, c := range cases {
		cmd := &cobra.Command{Use: "get"}
		cmd.Flags().StringP("output", "o", "", "")
		cmd.Flags().String("format", "", "")
		if err := cmd.ParseFlags(c.args); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd.SetErr(&stderr)
		warnTokenOverridesSession(cmd, token)
		if got := strings.Contains(stderr.String(), "Your logged-in session is being overwritten by the token provided from the --token flag."); got != c.warn {
			t.Errorf("%v: warned=%v, want %v (stderr=%q)", c.args, got, c.warn, stderr.String())
		}
		if !c.warn && stderr.Len() != 0 {
			t.Errorf("%v: stderr must stay empty for the structured error, got %q", c.args, stderr.String())
		}
	}
}
