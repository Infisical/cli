/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestProcessSecretsSetArgsReadsFileValues(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("expected-value"), 0o600))

	processedArgs, err := processSecretsSetArgs([]string{"MY_KEY=@" + filePath})

	require.NoError(t, err)
	require.Equal(t, []string{"MY_KEY=expected-value"}, processedArgs)
}

func TestProcessSecretsSetArgsEscapesFileValues(t *testing.T) {
	processedArgs, err := processSecretsSetArgs([]string{`MY_KEY=\@/tmp/secret.txt`})

	require.NoError(t, err)
	require.Equal(t, []string{"MY_KEY=@/tmp/secret.txt"}, processedArgs)
}

func TestRunSecretsSetUsesProcessedArgsForMachineIdentityTokens(t *testing.T) {
	for _, token := range []string{"st.a.b.c", "ua.test-token"} {
		t.Run(token[:2], func(t *testing.T) {
			var requestBody struct {
				SecretValue string `json:"secretValue"`
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v2/service-token":
					_, err := w.Write([]byte(`{"workspace":"project-id","scopes":[]}`))
					require.NoError(t, err)
				case r.Method == http.MethodGet && r.URL.Path == "/v4/secrets":
					_, err := w.Write([]byte(`{"secrets":[],"imports":[]}`))
					require.NoError(t, err)
				case r.Method == http.MethodPost && r.URL.Path == "/v3/secrets/raw/MY_KEY":
					require.NoError(t, json.NewDecoder(r.Body).Decode(&requestBody))
					w.WriteHeader(http.StatusOK)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)

			previousURL := config.INFISICAL_URL
			config.INFISICAL_URL = server.URL
			t.Cleanup(func() { config.INFISICAL_URL = previousURL })

			filePath := filepath.Join(t.TempDir(), "secret.txt")
			require.NoError(t, os.WriteFile(filePath, []byte("expected-value"), 0o600))

			cmd := newSecretsSetTestCommand(t, token)
			runSecretsSet(cmd, []string{"MY_KEY=@" + filePath})

			require.Equal(t, "expected-value", requestBody.SecretValue)
		})
	}
}

func newSecretsSetTestCommand(t *testing.T, token string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("token", token, "")
	cmd.Flags().String("projectId", "project-id", "")
	cmd.Flags().String("path", "/", "")
	cmd.Flags().String("type", "shared", "")
	cmd.Flags().String("file", "", "")
	cmd.Flags().StringArray("tag", nil, "")
	cmd.Flags().Bool("show-values", false, "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().StringP("env", "e", "dev", "")
	return cmd
}
