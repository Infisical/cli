package cmd

import (
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func envSliceToMap(entries []string) map[string]string {
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		if parts := strings.SplitN(entry, "=", 2); len(parts) == 2 {
			out[parts[0]] = parts[1]
		}
	}
	return out
}

func TestFormatSecretsForShellMultiPathPrecedenceAndDeduplication(t *testing.T) {
	secrets := []models.SingleEnvironmentVariable{
		{Key: "SHARED_KEY", Value: "from-global", SecretPath: "/global"},
		{Key: "GLOBAL_ONLY", Value: "g1", SecretPath: "/global"},
		{Key: "SHARED_KEY", Value: "from-app", SecretPath: "/app"},
		{Key: "APP_ONLY", Value: "a1", SecretPath: "/app"},
	}

	res := formatSecretsForShell(secrets)
	envMap := envSliceToMap(res.Variables)

	assert.Equal(t, "from-app", envMap["SHARED_KEY"], "later path should override earlier path for duplicate keys")
	assert.Equal(t, "g1", envMap["GLOBAL_ONLY"])
	assert.Equal(t, "a1", envMap["APP_ONLY"])
	assert.Equal(t, 3, res.SecretsCount, "SecretsCount should reflect unique deduplicated Infisical keys")

	// ETag should depend only on the effective deduplicated secrets, not shadowed earlier-path values.
	shadowChanged := []models.SingleEnvironmentVariable{
		{Key: "SHARED_KEY", Value: "different-shadowed-value", SecretPath: "/global"},
		{Key: "GLOBAL_ONLY", Value: "g1", SecretPath: "/global"},
		{Key: "SHARED_KEY", Value: "from-app", SecretPath: "/app"},
		{Key: "APP_ONLY", Value: "a1", SecretPath: "/app"},
	}
	resShadowChanged := formatSecretsForShell(shadowChanged)
	assert.Equal(t, res.ETag, resShadowChanged.ETag, "ETag should be deterministic across duplicate multi-path keys")

	effectiveChanged := []models.SingleEnvironmentVariable{
		{Key: "SHARED_KEY", Value: "from-global", SecretPath: "/global"},
		{Key: "GLOBAL_ONLY", Value: "g1", SecretPath: "/global"},
		{Key: "SHARED_KEY", Value: "updated-app-value", SecretPath: "/app"},
		{Key: "APP_ONLY", Value: "a1", SecretPath: "/app"},
	}
	resEffectiveChanged := formatSecretsForShell(effectiveChanged)
	assert.NotEqual(t, res.ETag, resEffectiveChanged.ETag, "ETag should change when effective merged value changes")
}

func TestRunCmdMultiPathFlagHelpAndParsing(t *testing.T) {
	cmd := buildRunCmd()
	pathFlag := cmd.Flags().Lookup("path")
	require.NotNil(t, pathFlag)
	assert.Contains(t, pathFlag.Usage, "later paths override earlier ones")

	require.NoError(t, cmd.Flags().Set("path", "/global"))
	require.NoError(t, cmd.Flags().Set("path", "/app"))

	paths, err := cmd.Flags().GetStringArray("path")
	require.NoError(t, err)
	assert.Equal(t, []string{"/global", "/app"}, paths)
}
