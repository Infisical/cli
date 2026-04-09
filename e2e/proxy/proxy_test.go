package proxy_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/infisical/cli/e2e-tests/packages/client"
	proxyHelpers "github.com/infisical/cli/e2e-tests/proxy"
	helpers "github.com/infisical/cli/e2e-tests/util"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ProxyTestConfig holds configuration for proxy tests
type ProxyTestConfig struct {
	ListenAddress                string
	TLSEnabled                   bool
	TLSCertFile                  string
	TLSKeyFile                   string
	AccessTokenCheckInterval     string
	StaticSecretsRefreshInterval string
	PollingFallbackInterval      string
	UseSSE                       bool
	ClientID                     string
	ClientSecret                 string
}

// DefaultProxyTestConfig returns default test configuration
func DefaultProxyTestConfig() ProxyTestConfig {
	return ProxyTestConfig{
		ListenAddress:                fmt.Sprintf("localhost:%d", helpers.GetFreePort()),
		TLSEnabled:                   false,
		AccessTokenCheckInterval:     "5s",
		StaticSecretsRefreshInterval: "5s",
	}
}

// SSEProxyTestConfig returns test configuration with SSE enabled
func SSEProxyTestConfig() ProxyTestConfig {
	config := DefaultProxyTestConfig()
	config.UseSSE = true
	config.PollingFallbackInterval = "10s"
	return config
}

// startProxy starts the proxy command and returns it
func startProxy(t *testing.T, ctx context.Context, infisicalURL string, config ProxyTestConfig, identityToken string) *helpers.Command {
	args := []string{
		"proxy", "start",
		"--log-level", "debug",
		"--domain", infisicalURL,
		"--listen-address", config.ListenAddress,
		fmt.Sprintf("--tls-enabled=%v", config.TLSEnabled),
		"--access-token-check-interval", config.AccessTokenCheckInterval,
		"--static-secrets-refresh-interval", config.StaticSecretsRefreshInterval,
	}

	if config.TLSEnabled && config.TLSCertFile != "" && config.TLSKeyFile != "" {
		args = append(args, "--tls-cert-file", config.TLSCertFile)
		args = append(args, "--tls-key-file", config.TLSKeyFile)
	}

	if config.UseSSE {
		args = append(args, "--enable-event-subscriptions")
		args = append(args, "--client-id", config.ClientID)
		args = append(args, "--client-secret", config.ClientSecret)
		if config.PollingFallbackInterval != "" {
			args = append(args, "--polling-fallback-interval", config.PollingFallbackInterval)
		}
	}

	proxyCmd := helpers.Command{
		Test: t,
		Args: args,
		Env:  map[string]string{},
	}
	proxyCmd.Start(ctx)

	// wait for proxy to start listening
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &proxyCmd,
		ExpectedString:   "Infisical proxy server starting",
		Timeout:          30 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "Proxy failed to start")

	return &proxyCmd
}

// setupProxyTest sets up the common test
func setupProxyTest(t *testing.T, ctx context.Context, proxyConfig ProxyTestConfig) (*helpers.InfisicalService, *proxyHelpers.ProxyTestHelper, *helpers.Command, string, string, helpers.MachineIdentity) {
	infisical := helpers.NewInfisicalService().Up(t, ctx)

	// create machine identity with token auth (and universal auth if SSE is enabled)
	identityOpts := []helpers.MachineIdentityOption{helpers.WithTokenAuth()}
	if proxyConfig.UseSSE {
		identityOpts = append(identityOpts, helpers.WithUniversalAuth())
	}
	identity := infisical.CreateMachineIdentity(t, ctx, identityOpts...)
	require.NotNil(t, identity.TokenAuthToken)
	identityToken := *identity.TokenAuthToken

	if proxyConfig.UseSSE {
		require.NotNil(t, identity.UniversalAuthClientId)
		require.NotNil(t, identity.UniversalAuthClientSecret)
		proxyConfig.ClientID = *identity.UniversalAuthClientId
		proxyConfig.ClientSecret = *identity.UniversalAuthClientSecret
	}

	// create API client with identity token to create the project
	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(identityToken)
	require.NoError(t, err)

	identityClient, err := client.NewClientWithResponses(
		infisical.ApiUrl(t),
		client.WithHTTPClient(&http.Client{}),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	// create project using identity token (identity automatically gets access to projects when the identity creates them)
	projectType := client.SecretManager
	projectResp, err := identityClient.CreateProjectWithResponse(ctx, client.CreateProjectJSONRequestBody{
		ProjectName: "proxy-test-" + helpers.RandomSlug(2),
		Type:        &projectType,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, projectResp.StatusCode(), "Failed to create project: %s", string(projectResp.Body))
	projectID := projectResp.JSON200.Project.Id
	slog.Info("Created project", "id", projectID)

	// start the proxy

	proxyCmd := startProxy(t, ctx, infisical.ApiUrl(t), proxyConfig, identityToken)
	t.Cleanup(proxyCmd.Stop)

	// build proxy URL
	proxyURL := "http://" + proxyConfig.ListenAddress
	if proxyConfig.TLSEnabled {
		proxyURL = "https://" + proxyConfig.ListenAddress
	}

	// create test helper with both proxy and direct API clients
	helper := proxyHelpers.NewProxyTestHelper(t, proxyURL, infisical.ApiUrl(t), identityToken, projectID)

	return infisical, helper, proxyCmd, identityToken, proxyURL, identity
}

func TestProxy_CacheHitMiss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, DefaultProxyTestConfig())

	// create a test secret
	secret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "TEST_SECRET_",
	})
	helper.CreateSecretWithApi(ctx, secret)

	// first request - should be cache miss
	slog.Info("Making first request (expecting cache miss)")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotNil(t, resp1.JSON200)
	require.NotEmpty(t, resp1.JSON200.Secrets)

	// verify secret value
	var foundSecret bool
	for _, s := range resp1.JSON200.Secrets {
		if s.SecretKey == secret.SecretKey {
			assert.Equal(t, secret.SecretValue, s.SecretValue)
			foundSecret = true
			break
		}
	}
	require.True(t, foundSecret, "Secret not found in response")

	// wait and check for "Cache miss" in logs
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Cache miss",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// second request - should be cache hit
	slog.Info("Making second request (expecting cache hit)")
	resp2 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp2.StatusCode())
	require.NotNil(t, resp2.JSON200)

	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Cache hit",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// verify both responses contain the same data
	assert.Equal(t, len(resp1.JSON200.Secrets), len(resp2.JSON200.Secrets))
}

func TestProxy_MutationPurging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, DefaultProxyTestConfig())

	initialSecret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "MUTATION_TEST_",
	})
	helper.CreateSecretWithApi(ctx, initialSecret)

	// cache the secret by fetching it
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())

	var foundInitial bool
	for _, s := range resp1.JSON200.Secrets {
		if s.SecretKey == initialSecret.SecretKey {
			assert.Equal(t, initialSecret.SecretValue, s.SecretValue)
			foundInitial = true
			break
		}
	}
	require.True(t, foundInitial, "Initial secret not found")

	helper.GetSecretsWithProxy(ctx)

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Cache hit",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// update the secret through the proxy (this should purge the cache)
	slog.Info("Updating secret via proxy (should purge cache)")

	updatedSecret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		PresetName: initialSecret.SecretKey,
	})
	updateResp := helper.UpdateSecretWithProxy(ctx, updatedSecret)
	require.Equal(t, http.StatusOK, updateResp.StatusCode())

	// wait for purging to happen

	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "purged",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// next request should be cache miss (because cache was purged)
	slog.Info("Fetching secret after update (expecting cache miss)")
	resp3 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp3.StatusCode())

	// verify the updated value
	var foundUpdated bool
	for _, s := range resp3.JSON200.Secrets {
		if s.SecretKey == initialSecret.SecretKey {
			assert.Equal(t, updatedSecret.SecretValue, s.SecretValue)
			foundUpdated = true
			break
		}
	}
	require.True(t, foundUpdated, "Updated secret not found")
}

func TestProxy_DeleteMutationPurging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, DefaultProxyTestConfig())

	// create a test secret
	secret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "DELETE_TEST_",
	})
	helper.CreateSecretWithApi(ctx, secret)

	// cache the secret
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotEmpty(t, resp1.JSON200.Secrets)

	// verify cache hit on second request
	helper.GetSecretsWithProxy(ctx)

	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Cache hit",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// delete the secret through the proxy
	slog.Info("Deleting secret via proxy (should purge cache)")
	deleteResp := helper.DeleteSecretWithProxy(ctx, secret.SecretKey)
	require.Equal(t, http.StatusOK, deleteResp.StatusCode())

	// wait for purging
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "purged",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// next request should be cache miss
	slog.Info("Fetching secrets after delete (expecting cache miss)")
	resp3 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp3.StatusCode())

	// verify secret is gone
	for _, s := range resp3.JSON200.Secrets {
		require.NotEqual(t, secret.SecretKey, s.SecretKey, "Deleted secret should not be in response")
	}
}

func TestProxy_TokenInvalidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	config := DefaultProxyTestConfig()
	config.AccessTokenCheckInterval = "2s"

	_, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, config)

	// create and cache a secret
	secret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "TOKEN_TEST_",
	})
	helper.CreateSecretWithApi(ctx, secret)

	// cache the secret
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())

	helper.GetSecretsWithProxy(ctx)

	// verify it's cached
	cacheHitResult := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Cache hit",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, cacheHitResult)

	// wait for the token validation loop to run
	slog.Info("Waiting for access token validation loop to run")
	tokenValidationResult := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Access token validation completed",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	assert.Equal(t, helpers.WaitSuccess, tokenValidationResult, "Token validation loop should have run")
}

func TestProxy_HighAvailability(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infisical, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, DefaultProxyTestConfig())

	// create and cache a secret
	secret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "HA_TEST_",
	})
	helper.CreateSecretWithApi(ctx, secret)

	// cache the secret
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotEmpty(t, resp1.JSON200.Secrets)

	// verify it's cached
	helper.GetSecretsWithProxy(ctx)

	cacheHitResult := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Cache hit",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, cacheHitResult)

	// stop the Infisical backend to simulate unavailability
	slog.Info("Stopping Infisical backend to simulate unavailability")
	backendContainer, err := infisical.Compose().ServiceContainer(ctx, "backend")
	require.NoError(t, err)
	err = backendContainer.Stop(ctx, nil)
	require.NoError(t, err)

	// wait for container to actually stop
	require.Eventually(t, func() bool {
		state, err := backendContainer.State(ctx)
		if err != nil {
			return false
		}
		return !state.Running
	}, 60*time.Second, 200*time.Millisecond, "Backend container should have stopped")
	slog.Info("Backend stopped")

	// request should still succeed from cache (high availability)
	slog.Info("Requesting secrets while backend is down (expecting cache to serve)")
	resp3 := helper.GetSecretsWithProxy(ctx)

	// the proxy should serve from cache
	require.Equal(t, http.StatusOK, resp3.StatusCode(), "Proxy should serve cached data when backend is unavailable")

	// verify we got the cached secret
	var foundSecret bool
	for _, s := range resp3.JSON200.Secrets {
		if s.SecretKey == secret.SecretKey {
			assert.Equal(t, secret.SecretValue, s.SecretValue)
			foundSecret = true
			break
		}
	}
	require.True(t, foundSecret, "Cached secret should still be accessible when backend is down")

	slog.Info("High availability test passed - cache served data while backend was down")

	// tear down compose stack so subsequent tests get fresh containers
	// the DB must be removed, otherwise pg-boss fails with "multiple primary keys for table job"
	slog.Info("Tearing down compose stack for clean state in subsequent tests")
	err = infisical.DownWithForce(ctx)
	require.NoError(t, err, "Failed to tear down compose stack")
	slog.Info("Compose stack torn down")
}

func TestProxy_BackgroundRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, DefaultProxyTestConfig())

	// create a test initialSecret
	initialSecret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "REFRESH_TEST_",
	})
	helper.CreateSecretWithApi(ctx, initialSecret)

	// cache the secret via proxy
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())

	// update the secret directly through API (not through proxy)
	slog.Info("Updating secret directly through API")

	updatedSecret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		PresetName: initialSecret.SecretKey,
	})

	helper.UpdateSecretWithApi(ctx, updatedSecret)

	slog.Info("Waiting for proxy cache to reflect updated value")
	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: proxyCmd,
		Timeout:          20 * time.Second,
		Interval:         2 * time.Second,
		Condition: func() helpers.ConditionResult {
			resp := helper.GetSecretsWithProxy(ctx)
			if resp.StatusCode() != http.StatusOK {
				return helpers.ConditionWait
			}
			for _, s := range resp.JSON200.Secrets {
				if s.SecretKey == updatedSecret.SecretKey && s.SecretValue == updatedSecret.SecretValue {
					slog.Info("Cache now contains updated value")
					return helpers.ConditionSuccess
				}
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, waitResult)

	slog.Info(fmt.Sprintf("Initial secret value: %s", initialSecret.SecretValue))
	slog.Info(fmt.Sprintf("Updated secret value: %s", updatedSecret.SecretValue))

	// verify the proxy is still running
	require.True(t, proxyCmd.IsRunning(), "Proxy should still be running")

	// fetch from proxy - should return the updated value
	slog.Info("Fetching secret after background refresh")
	resp2 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp2.StatusCode())

	var foundUpdated bool
	for _, s := range resp2.JSON200.Secrets {
		if s.SecretKey == updatedSecret.SecretKey {
			assert.Equal(t, updatedSecret.SecretValue, s.SecretValue, "Cache should have been refreshed with new value")
			foundUpdated = true
			break
		}
	}
	require.True(t, foundUpdated, "Updated secret should be found after background refresh")
}

func TestProxy_MultipleSecrets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, _, _, _, _ := setupProxyTest(t, ctx, DefaultProxyTestConfig())

	var secrets []proxyHelpers.Secret
	for i := 0; i < 3; i++ {
		secrets = append(secrets, helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
			Prefix: fmt.Sprintf("MULTI_SECRET_%d_", i),
		}))
	}

	for _, secret := range secrets {
		helper.CreateSecretWithApi(ctx, secret)
	}

	// fetch all secrets via proxy
	slog.Info("Fetching all secrets via proxy")
	resp := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp.StatusCode())
	require.GreaterOrEqual(t, len(resp.JSON200.Secrets), len(secrets))

	// verify all secrets are present
	for _, secret := range secrets {
		var found bool
		for _, s := range resp.JSON200.Secrets {
			if s.SecretKey == secret.SecretKey {
				assert.Equal(t, secret.SecretValue, s.SecretValue)
				found = true
				break
			}
		}
		require.True(t, found, "Secret %s should be present", secret.SecretKey)
	}
}

func TestProxy_SingleSecretEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, DefaultProxyTestConfig())

	// create a test secret
	secret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "SINGLE_SECRET_",
	})
	helper.CreateSecretWithApi(ctx, secret)

	// fetch single secret via proxy
	slog.Info("Fetching single secret via proxy")
	resp1 := helper.GetSecretByNameWithProxy(ctx, secret.SecretKey)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotNil(t, resp1.JSON200)
	assert.Equal(t, secret.SecretKey, resp1.JSON200.Secret.SecretKey)
	assert.Equal(t, secret.SecretValue, resp1.JSON200.Secret.SecretValue)

	resp2 := helper.GetSecretByNameWithProxy(ctx, secret.SecretKey)

	// second request should be cache hit
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Cache hit",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	require.Equal(t, http.StatusOK, resp2.StatusCode())
}

func TestProxy_SSECacheUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, SSEProxyTestConfig())

	// wait for SSE manager initialization
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "SSE manager initialized",
		Timeout:          30 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// create secret via API (not proxy)
	initialSecret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "SSE_UPDATE_TEST_",
	})
	helper.CreateSecretWithApi(ctx, initialSecret)

	// fetch via proxy -> cache miss, now cached
	slog.Info("Fetching secret via proxy (expecting cache miss)")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotNil(t, resp1.JSON200)

	var foundInitial bool
	for _, s := range resp1.JSON200.Secrets {
		if s.SecretKey == initialSecret.SecretKey {
			assert.Equal(t, initialSecret.SecretValue, s.SecretValue)
			foundInitial = true
			break
		}
	}
	require.True(t, foundInitial, "Initial secret not found in response")

	// fetch again -> cache hit
	helper.GetSecretsWithProxy(ctx)
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Cache hit",
		Timeout:          10 * time.Second,
		Interval:         200 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// wait for SSE connection (demand-driven, triggered by first fetch)
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "SSE connection established",
		Timeout:          30 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// update secret via API (not proxy) -> SSE event fires
	slog.Info("Updating secret via API (expecting SSE event)")
	updatedSecret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		PresetName: initialSecret.SecretKey,
	})
	helper.UpdateSecretWithApi(ctx, updatedSecret)

	// wait for SSE event processing
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Processing SSE event",
		Timeout:          15 * time.Second,
		Interval:         500 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// wait for refetch to complete
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "SSE refetch completed",
		Timeout:          15 * time.Second,
		Interval:         500 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// fetch via proxy -> should return updated value (repopulated by SSE refetch)
	slog.Info("Fetching secret via proxy after SSE update")
	resp3 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp3.StatusCode())
	require.NotNil(t, resp3.JSON200)

	var foundUpdated bool
	for _, s := range resp3.JSON200.Secrets {
		if s.SecretKey == initialSecret.SecretKey {
			assert.Equal(t, updatedSecret.SecretValue, s.SecretValue, "Cache should reflect SSE-driven update")
			foundUpdated = true
			break
		}
	}
	require.True(t, foundUpdated, "Updated secret not found after SSE event")
}

func TestProxy_SSEConnectionRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infisical, helper, proxyCmd, _, _, _ := setupProxyTest(t, ctx, SSEProxyTestConfig())

	// create and cache a secret to trigger SSE subscription
	secret := helper.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "SSE_RECOVERY_",
	})
	helper.CreateSecretWithApi(ctx, secret)

	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotEmpty(t, resp1.JSON200.Secrets)

	// wait for SSE connection established
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "SSE connection established",
		Timeout:          30 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// stop the Infisical backend container (SSE connection drops)
	slog.Info("Stopping Infisical backend to break SSE connection")
	backendContainer, err := infisical.Compose().ServiceContainer(ctx, "backend")
	require.NoError(t, err)
	err = backendContainer.Stop(ctx, nil)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		state, err := backendContainer.State(ctx)
		if err != nil {
			return false
		}
		return !state.Running
	}, 60*time.Second, 200*time.Millisecond, "Backend container should have stopped")
	slog.Info("Backend stopped")

	// wait for SSE connection loss
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "SSE connection lost",
		Timeout:          30 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "SSE connection loss should be detected")

	// restart the backend container
	slog.Info("Restarting Infisical backend")
	err = backendContainer.Start(ctx)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		state, err := backendContainer.State(ctx)
		if err != nil {
			return false
		}
		return state.Running
	}, 60*time.Second, 200*time.Millisecond, "Backend container should have restarted")
	slog.Info("Backend restarted")

	// trigger normal client traffic so EnsureSubscription can recreate SSE if retries were exhausted
	slog.Info("Fetching secrets after backend restart to trigger SSE re-subscription")
	respAfterRestart := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, respAfterRestart.StatusCode())

	// wait for SSE re-subscription after the fetch trigger
	slog.Info("Waiting for SSE re-subscription after fetch trigger")
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "SSE connection established",
		Timeout:          120 * time.Second,
	})
	require.Equal(t, helpers.WaitSuccess, result, "SSE should re-subscribe after backend restart and a trigger fetch")

	// verify proxy is still functional
	slog.Info("Verifying proxy still works after SSE reconnection")
	respAfterReconnect := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, respAfterReconnect.StatusCode())

	require.True(t, proxyCmd.IsRunning(), "Proxy should still be running")

	// tear down compose stack for clean state in subsequent tests
	slog.Info("Tearing down compose stack for clean state")
	err = infisical.DownWithForce(ctx)
	require.NoError(t, err, "Failed to tear down compose stack")
}

func TestProxy_SSEMultipleProjects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infisical, helper1, proxyCmd, identityToken, proxyURL, _ := setupProxyTest(t, ctx, SSEProxyTestConfig())

	// create a second project using the same identity
	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(identityToken)
	require.NoError(t, err)

	identityClient, err := client.NewClientWithResponses(
		infisical.ApiUrl(t),
		client.WithHTTPClient(&http.Client{}),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	projectType := client.SecretManager
	project2Resp, err := identityClient.CreateProjectWithResponse(ctx, client.CreateProjectJSONRequestBody{
		ProjectName: "proxy-sse-test-2-" + helpers.RandomSlug(2),
		Type:        &projectType,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, project2Resp.StatusCode(), "Failed to create project 2: %s", string(project2Resp.Body))
	project2ID := project2Resp.JSON200.Project.Id
	slog.Info("Created project 2", "id", project2ID)

	// create helper2 for project 2, pointed at the same proxy
	helper2 := proxyHelpers.NewProxyTestHelper(t, proxyURL, infisical.ApiUrl(t), identityToken, project2ID)

	// create secrets in each project
	secret1 := helper1.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "SSE_MULTI_P1_",
	})
	helper1.CreateSecretWithApi(ctx, secret1)

	secret2 := helper2.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		Prefix: "SSE_MULTI_P2_",
	})
	helper2.CreateSecretWithApi(ctx, secret2)

	// fetch from each project via proxy -> triggers SSE subscription for each
	slog.Info("Fetching secrets from project 1 via proxy")
	resp1 := helper1.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())

	slog.Info("Fetching secrets from project 2 via proxy")
	resp2 := helper2.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp2.StatusCode())

	// verify two separate SSE connections established (one per project)
	slog.Info("Waiting for two SSE connections to be established")
	waitResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: proxyCmd,
		Timeout:          30 * time.Second,
		Interval:         1 * time.Second,
		Condition: func() helpers.ConditionResult {
			if strings.Count(proxyCmd.Stderr(), "SSE connection established") >= 2 {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, waitResult, "Two SSE connections should be established")

	// update secret in project 1 via API
	slog.Info("Updating secret in project 1 via API")
	updatedSecret1 := helper1.GenerateSecret(proxyHelpers.GenerateSecretOptions{
		PresetName: secret1.SecretKey,
	})
	helper1.UpdateSecretWithApi(ctx, updatedSecret1)

	// wait for SSE event processing
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "SSE refetch completed",
		Timeout:          15 * time.Second,
		Interval:         500 * time.Millisecond,
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// verify project 1 has updated value
	slog.Info("Verifying project 1 has updated value")
	resp1After := helper1.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1After.StatusCode())

	var foundUpdated bool
	for _, s := range resp1After.JSON200.Secrets {
		if s.SecretKey == secret1.SecretKey {
			assert.Equal(t, updatedSecret1.SecretValue, s.SecretValue, "Project 1 secret should be updated via SSE")
			foundUpdated = true
			break
		}
	}
	require.True(t, foundUpdated, "Updated secret not found in project 1")

	// verify project 2 still has original value (not invalidated)
	slog.Info("Verifying project 2 still has original value")
	resp2After := helper2.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp2After.StatusCode())

	var foundOriginal bool
	for _, s := range resp2After.JSON200.Secrets {
		if s.SecretKey == secret2.SecretKey {
			assert.Equal(t, secret2.SecretValue, s.SecretValue, "Project 2 secret should be unchanged")
			foundOriginal = true
			break
		}
	}
	require.True(t, foundOriginal, "Original secret not found in project 2")
}
