package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseEnvMap(entries []string) map[string]string {
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		if parts := strings.SplitN(entry, "=", 2); len(parts) == 2 {
			out[parts[0]] = parts[1]
		}
	}
	return out
}

func TestFormatSecretsForShellInjectsProjectIDWithoutOverwrite(t *testing.T) {
	secrets := []models.SingleEnvironmentVariable{
		{Key: "API_KEY", Value: "secret-val"},
		{Key: util.INFISICAL_PROJECT_ID_NAME, Value: "attempted-override"},
	}

	res := formatSecretsForShell(secrets, "proj-actual-123")
	envMap := parseEnvMap(res.Variables)

	assert.Equal(t, "secret-val", envMap["API_KEY"])
	assert.Equal(t, "proj-actual-123", envMap[util.INFISICAL_PROJECT_ID_NAME], "resolved project ID must not be overwritten by a user secret")
}

func TestResolveProjectIDForInjectionPrecedenceAndWorkspaceFallbacks(t *testing.T) {
	t.Run("explicit request WorkspaceId takes precedence", func(t *testing.T) {
		got := resolveProjectIDForInjection(
			models.GetMultiPathSecretsParameters{WorkspaceId: "proj-explicit"},
			[]models.SingleEnvironmentVariable{{Key: "A", WorkspaceId: "proj-from-secret"}},
			"",
			nil,
		)
		assert.Equal(t, "proj-explicit", got)
	})

	t.Run("secret WorkspaceId used when explicit WorkspaceId is empty", func(t *testing.T) {
		got := resolveProjectIDForInjection(
			models.GetMultiPathSecretsParameters{},
			[]models.SingleEnvironmentVariable{{Key: "A", WorkspaceId: "proj-from-secret"}},
			"",
			&models.TokenDetails{Type: util.SERVICE_TOKEN_IDENTIFIER, Token: "st.example"},
		)
		assert.Equal(t, "proj-from-secret", got)
	})

	t.Run("projectConfigDir resolves legacy .infisical.json", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, util.LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME),
			[]byte(`{"workspaceId":"proj-from-json"}`),
			0o600,
		))

		got := resolveProjectIDForInjection(models.GetMultiPathSecretsParameters{}, nil, dir, nil)
		assert.Equal(t, "proj-from-json", got)
	})

	t.Run("projectConfigDir resolves .infisical.yaml over legacy .infisical.json", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, util.LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME),
			[]byte(`{"workspaceId":"proj-from-json"}`),
			0o600,
		))
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME),
			[]byte("version: 1\nsecrets-management:\n  project-id: proj-from-yaml\n"),
			0o600,
		))

		got := resolveProjectIDForInjection(models.GetMultiPathSecretsParameters{}, nil, dir, nil)
		assert.Equal(t, "proj-from-yaml", got)
	})

	t.Run("cwd walk resolves workspace config when projectConfigDir is empty", func(t *testing.T) {
		dir := t.TempDir()
		nested := filepath.Join(dir, "sub", "dir")
		require.NoError(t, os.MkdirAll(nested, 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, util.LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME),
			[]byte(`{"workspaceId":"proj-walked-json"}`),
			0o600,
		))

		origWD, err := os.Getwd()
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Chdir(origWD) })
		require.NoError(t, os.Chdir(nested))

		got := resolveProjectIDForInjection(models.GetMultiPathSecretsParameters{}, nil, "", nil)
		assert.Equal(t, "proj-walked-json", got)
	})

	t.Run("service token does not leak local workspace file when zero secrets returned", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, util.LEGACY_INFISICAL_WORKSPACE_CONFIG_FILE_NAME),
			[]byte(`{"workspaceId":"unrelated-local-proj"}`),
			0o600,
		))

		got := resolveProjectIDForInjection(
			models.GetMultiPathSecretsParameters{},
			nil,
			dir,
			&models.TokenDetails{Type: util.SERVICE_TOKEN_IDENTIFIER, Token: "st.example"},
		)
		assert.Equal(t, "", got)
	})
}
