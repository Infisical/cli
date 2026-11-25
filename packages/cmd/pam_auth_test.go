package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestPAMTokenIgnoresTheGenericTokenVariable(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	addPAMAuthFlags(cmd)
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN", "")
	t.Setenv("INFISICAL_TOKEN", "")
	t.Setenv("TOKEN", "unrelated")
	if token := pamToken(cmd); token != nil {
		t.Fatalf("TOKEN was used: %+v", token)
	}

	t.Setenv("INFISICAL_TOKEN", "from-env")
	if token := pamToken(cmd); token == nil || token.Token != "from-env" {
		t.Fatalf("INFISICAL_TOKEN was not used: %+v", token)
	}

	_ = cmd.Flags().Set("token", "from-flag")
	if token := pamToken(cmd); token == nil || token.Token != "from-flag" || token.Source != "--token flag" {
		t.Fatalf("--token did not win: %+v", token)
	}
	if !rejectsServiceTokens(cmd) || !usesPAMAuth(cmd) {
		t.Fatal("PAM commands must be marked as rejecting service tokens and using PAM auth")
	}
}
