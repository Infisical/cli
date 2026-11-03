package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

func TestProcessSecretsSetArgs(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(filePath, []byte("file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := processSecretsSetArgs([]string{
		"FROM_FILE=@" + filePath,
		"ESCAPED=\\@literal",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"FROM_FILE=file-value\n",
		"ESCAPED=@literal",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d processed arguments, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("processed argument %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestProcessSecretsSetArgsMissingFile(t *testing.T) {
	_, err := processSecretsSetArgs([]string{"SECRET=@" + filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestRunSecretsSetPassesProcessedArgsForTokenAuth(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(filePath, []byte("file-value"), 0o600); err != nil {
		t.Fatal(err)
	}

	originalSetRawSecrets := setRawSecrets
	t.Cleanup(func() {
		setRawSecrets = originalSetRawSecrets
	})

	var capturedArgs []string
	var capturedTokenType string
	setRawSecrets = func(args []string, _ string, _ string, _ string, _ string, token *models.TokenDetails, _ string, _ []string) ([]models.SecretSetOperation, error) {
		capturedArgs = args
		capturedTokenType = token.Type
		return nil, nil
	}

	tests := []struct {
		name      string
		token     string
		tokenType string
	}{
		{name: "service token", token: "st.test", tokenType: util.SERVICE_TOKEN_IDENTIFIER},
		{name: "universal auth token", token: "ua.test", tokenType: util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("token", tt.token, "")
			cmd.Flags().String("projectId", "project-id", "")
			cmd.Flags().String("env", "dev", "")
			cmd.Flags().String("path", "/", "")
			cmd.Flags().String("type", util.SECRET_TYPE_SHARED, "")
			cmd.Flags().String("file", "", "")
			cmd.Flags().StringArray("tag", nil, "")
			cmd.Flags().Bool("show-values", false, "")
			cmd.Flags().String("output", "", "")

			runSecretsSet(cmd, []string{
				"FROM_FILE=@" + filePath,
				"ESCAPED=\\@literal",
			})

			if capturedTokenType != tt.tokenType {
				t.Fatalf("captured token type %q, want %q", capturedTokenType, tt.tokenType)
			}
			want := []string{"FROM_FILE=file-value", "ESCAPED=@literal"}
			if !reflect.DeepEqual(capturedArgs, want) {
				t.Fatalf("captured args %q, want %q", capturedArgs, want)
			}
		})
	}
}
