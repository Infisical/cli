package proxy_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/infisical/cli/e2e-tests/packages/client"
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
}

// DefaultProxyTestConfig returns default test configuration
func DefaultProxyTestConfig() ProxyTestConfig {
	return ProxyTestConfig{
		ListenAddress:                fmt.Sprintf("localhost:%d", getFreePort()),
		TLSEnabled:                   false,
		AccessTokenCheckInterval:     "5s",
		StaticSecretsRefreshInterval: "5s",
	}
}

// getFreePort finds an available port
func getFreePort() int {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// ProxyTestHelper provides helper methods for proxy tests
type ProxyTestHelper struct {
	t           *testing.T
	proxyClient client.ClientWithResponsesInterface // client pointing to proxy
	apiClient   client.ClientWithResponsesInterface // client pointing to Infisical directly
	projectID   string
	environment string
}

// NewProxyTestHelper creates a new test helper with clients for both proxy and direct API access
func NewProxyTestHelper(t *testing.T, proxyURL, infisicalURL, identityToken, projectID string) *ProxyTestHelper {
	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(identityToken)
	require.NoError(t, err)

	// client for requests through the proxy (to test caching)
	proxyClient, err := client.NewClientWithResponses(
		proxyURL,
		client.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	// client for direct API access
	apiClient, err := client.NewClientWithResponses(
		infisicalURL,
		client.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	return &ProxyTestHelper{
		t:           t,
		proxyClient: proxyClient,
		apiClient:   apiClient,
		projectID:   projectID,
		environment: "dev",
	}
}

// CreateSecretWithApi creates a secret directly through Infisical API (not through proxy)
func (h *ProxyTestHelper) CreateSecretWithApi(ctx context.Context, secretName, secretValue string) {
	secretPath := "/"
	resp, err := h.apiClient.CreateSecretV4WithResponse(ctx, secretName, client.CreateSecretV4JSONRequestBody{
		ProjectId:   h.projectID,
		Environment: h.environment,
		SecretValue: secretValue,
		SecretPath:  &secretPath,
	})
	require.NoError(h.t, err)
	require.Equal(h.t, http.StatusOK, resp.StatusCode(), "Failed to create secret: %s", string(resp.Body))
	slog.Info("Created secret", "name", secretName, "value", secretValue)
}

// UpdateSecretWithApi updates a secret directly through Infisical API (not through proxy)
func (h *ProxyTestHelper) UpdateSecretWithApi(ctx context.Context, secretName, newValue string) {
	secretPath := "/"
	resp, err := h.apiClient.UpdateSecretV4WithResponse(ctx, secretName, client.UpdateSecretV4JSONRequestBody{
		ProjectId:   h.projectID,
		Environment: h.environment,
		SecretValue: &newValue,
		SecretPath:  &secretPath,
	})
	require.NoError(h.t, err)
	require.Equal(h.t, http.StatusOK, resp.StatusCode(), "Failed to update secret: %s", string(resp.Body))
	slog.Info("Updated secret directly", "name", secretName, "newValue", newValue)
}

// GetSecretsWithProxy fetches secrets through the proxy
func (h *ProxyTestHelper) GetSecretsWithProxy(ctx context.Context) *client.ListSecretsV4Response {
	secretPath := "/"
	projectID := h.projectID
	environment := h.environment
	resp, err := h.proxyClient.ListSecretsV4WithResponse(ctx, &client.ListSecretsV4Params{
		ProjectId:   &projectID,
		Environment: &environment,
		SecretPath:  &secretPath,
	})
	require.NoError(h.t, err)
	return resp
}

// GetSecretByNameWithProxy fetches a single secret through the proxy
func (h *ProxyTestHelper) GetSecretByNameWithProxy(ctx context.Context, secretName string) *client.GetSecretByNameV4Response {
	secretPath := "/"
	environment := h.environment
	resp, err := h.proxyClient.GetSecretByNameV4WithResponse(ctx, secretName, &client.GetSecretByNameV4Params{
		ProjectId:   h.projectID,
		Environment: &environment,
		SecretPath:  &secretPath,
	})
	require.NoError(h.t, err)
	return resp
}

// UpdateSecretWithProxy updates a secret through the proxy (triggers mutation purging)
func (h *ProxyTestHelper) UpdateSecretWithProxy(ctx context.Context, secretName, newValue string) *client.UpdateSecretV4Response {
	secretPath := "/"
	resp, err := h.proxyClient.UpdateSecretV4WithResponse(ctx, secretName, client.UpdateSecretV4JSONRequestBody{
		ProjectId:   h.projectID,
		Environment: h.environment,
		SecretPath:  &secretPath,
		SecretValue: &newValue,
	})
	require.NoError(h.t, err)
	return resp
}

// DeleteSecretWithProxy deletes a secret through the proxy (triggers mutation purging)
func (h *ProxyTestHelper) DeleteSecretWithProxy(ctx context.Context, secretName string) *client.DeleteSecretV4Response {
	secretPath := "/"
	resp, err := h.proxyClient.DeleteSecretV4WithResponse(ctx, secretName, client.DeleteSecretV4JSONRequestBody{
		ProjectId:   h.projectID,
		Environment: h.environment,
		SecretPath:  &secretPath,
	})
	require.NoError(h.t, err)
	return resp
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
func setupProxyTest(t *testing.T, ctx context.Context) (*helpers.InfisicalService, *ProxyTestHelper, *helpers.Command, ProxyTestConfig) {
	infisical := helpers.NewInfisicalService().Up(t, ctx)

	// create machine identity with token auth
	identity := infisical.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity.TokenAuthToken)
	identityToken := *identity.TokenAuthToken

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
	config := DefaultProxyTestConfig()
	proxyCmd := startProxy(t, ctx, infisical.ApiUrl(t), config, identityToken)
	t.Cleanup(proxyCmd.Stop)

	// build proxy URL
	proxyURL := "http://" + config.ListenAddress
	if config.TLSEnabled {
		proxyURL = "https://" + config.ListenAddress
	}

	// create test helper with both proxy and direct API clients
	helper := NewProxyTestHelper(t, proxyURL, infisical.ApiUrl(t), identityToken, projectID)

	return infisical, helper, proxyCmd, config
}

// setupProxyTestWithConfig is like setupProxyTest but allows custom config
func setupProxyTestWithConfig(t *testing.T, ctx context.Context, config ProxyTestConfig) (*helpers.InfisicalService, *ProxyTestHelper, *helpers.Command) {
	infisical := helpers.NewInfisicalService().Up(t, ctx)

	// create machine identity with token auth
	identity := infisical.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity.TokenAuthToken)
	identityToken := *identity.TokenAuthToken

	// create API client with identity token
	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(identityToken)
	require.NoError(t, err)

	identityClient, err := client.NewClientWithResponses(
		infisical.ApiUrl(t),
		client.WithHTTPClient(&http.Client{}),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	// create project
	projectType := client.SecretManager
	projectResp, err := identityClient.CreateProjectWithResponse(ctx, client.CreateProjectJSONRequestBody{
		ProjectName: "proxy-test-" + helpers.RandomSlug(2),
		Type:        &projectType,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, projectResp.StatusCode())
	projectID := projectResp.JSON200.Project.Id

	proxyCmd := startProxy(t, ctx, infisical.ApiUrl(t), config, identityToken)
	t.Cleanup(proxyCmd.Stop)

	proxyURL := "http://" + config.ListenAddress
	if config.TLSEnabled {
		proxyURL = "https://" + config.ListenAddress
	}

	helper := NewProxyTestHelper(t, proxyURL, infisical.ApiUrl(t), identityToken, projectID)

	return infisical, helper, proxyCmd
}

func TestProxy_CacheHitMiss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _ := setupProxyTest(t, ctx)

	// create a test secret
	secretName := "TEST_SECRET_" + faker.Word()
	secretValue := faker.Password()
	helper.CreateSecretWithApi(ctx, secretName, secretValue)

	// first request - should be cache miss
	slog.Info("Making first request (expecting cache miss)")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotNil(t, resp1.JSON200)
	require.NotEmpty(t, resp1.JSON200.Secrets)

	// verify secret value
	var foundSecret bool
	for _, s := range resp1.JSON200.Secrets {
		if s.SecretKey == secretName {
			assert.Equal(t, secretValue, s.SecretValue)
			foundSecret = true
			break
		}
	}
	require.True(t, foundSecret, "Secret not found in response")

	// wait and check for "Cache miss" in logs
	time.Sleep(500 * time.Millisecond)
	assert.Contains(t, proxyCmd.Stderr(), "Cache miss", "First request should be a cache miss")

	// second request - should be cache hit
	slog.Info("Making second request (expecting cache hit)")
	resp2 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp2.StatusCode())
	require.NotNil(t, resp2.JSON200)

	// wait and check for "Cache hit" in logs
	time.Sleep(500 * time.Millisecond)
	assert.Contains(t, proxyCmd.Stderr(), "Cache hit", "Second request should be a cache hit")

	// verify both responses contain the same data
	assert.Equal(t, len(resp1.JSON200.Secrets), len(resp2.JSON200.Secrets))
}

func TestProxy_MutationPurging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _ := setupProxyTest(t, ctx)

	// create a test secret
	secretName := "MUTATION_TEST_" + faker.Word()
	initialValue := "initial_value"
	helper.CreateSecretWithApi(ctx, secretName, initialValue)

	// cache the secret by fetching it
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())

	var foundInitial bool
	for _, s := range resp1.JSON200.Secrets {
		if s.SecretKey == secretName {
			assert.Equal(t, initialValue, s.SecretValue)
			foundInitial = true
			break
		}
	}
	require.True(t, foundInitial, "Initial secret not found")

	// second request should be cache hit
	time.Sleep(500 * time.Millisecond)
	helper.GetSecretsWithProxy(ctx)
	time.Sleep(500 * time.Millisecond)
	require.Contains(t, proxyCmd.Stderr(), "Cache hit")

	// update the secret through the proxy (this should purge the cache)
	slog.Info("Updating secret via proxy (should purge cache)")
	updatedValue := "updated_value"
	updateResp := helper.UpdateSecretWithProxy(ctx, secretName, updatedValue)
	require.Equal(t, http.StatusOK, updateResp.StatusCode())

	// wait for purging to happen
	time.Sleep(1 * time.Second)
	require.Contains(t, proxyCmd.Stderr(), "purged", "Cache should have been purged after mutation")

	// next request should be cache miss (because cache was purged)
	slog.Info("Fetching secret after update (expecting cache miss)")
	resp3 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp3.StatusCode())

	// verify the updated value
	var foundUpdated bool
	for _, s := range resp3.JSON200.Secrets {
		if s.SecretKey == secretName {
			assert.Equal(t, updatedValue, s.SecretValue)
			foundUpdated = true
			break
		}
	}
	require.True(t, foundUpdated, "Updated secret not found")
}

func TestProxy_DeleteMutationPurging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _ := setupProxyTest(t, ctx)

	// create a test secret
	secretName := "DELETE_TEST_" + faker.Word()
	secretValue := faker.Password()
	helper.CreateSecretWithApi(ctx, secretName, secretValue)

	// cache the secret
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotEmpty(t, resp1.JSON200.Secrets)

	// verify cache hit on second request
	time.Sleep(500 * time.Millisecond)
	helper.GetSecretsWithProxy(ctx)
	time.Sleep(500 * time.Millisecond)
	require.Contains(t, proxyCmd.Stderr(), "Cache hit")

	// delete the secret through the proxy
	slog.Info("Deleting secret via proxy (should purge cache)")
	deleteResp := helper.DeleteSecretWithProxy(ctx, secretName)
	require.Equal(t, http.StatusOK, deleteResp.StatusCode())

	// wait for purging
	time.Sleep(1 * time.Second)
	require.Contains(t, proxyCmd.Stderr(), "purged")

	// next request should be cache miss
	slog.Info("Fetching secrets after delete (expecting cache miss)")
	resp3 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp3.StatusCode())

	// verify secret is gone
	for _, s := range resp3.JSON200.Secrets {
		require.NotEqual(t, secretName, s.SecretKey, "Deleted secret should not be in response")
	}
}

func TestProxy_TokenInvalidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	config := DefaultProxyTestConfig()
	config.AccessTokenCheckInterval = "2s"

	_, helper, proxyCmd := setupProxyTestWithConfig(t, ctx, config)

	// create and cache a secret
	secretName := "TOKEN_TEST_" + faker.Word()
	secretValue := faker.Password()
	helper.CreateSecretWithApi(ctx, secretName, secretValue)

	// cache the secret
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())

	// verify it's cached
	time.Sleep(500 * time.Millisecond)
	helper.GetSecretsWithProxy(ctx)
	time.Sleep(500 * time.Millisecond)
	require.Contains(t, proxyCmd.Stderr(), "Cache hit")

	// wait for the token validation loop to run
	slog.Info("Waiting for access token validation loop to run")
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: proxyCmd,
		ExpectedString:   "Access token validation completed",
		Timeout:          10 * time.Second,
	})
	assert.Equal(t, helpers.WaitSuccess, result, "Token validation loop should have run")
}

func TestProxy_HighAvailability(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infisical, helper, proxyCmd, _ := setupProxyTest(t, ctx)

	// create and cache a secret
	secretName := "HA_TEST_" + faker.Word()
	secretValue := faker.Password()
	helper.CreateSecretWithApi(ctx, secretName, secretValue)

	// cache the secret
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotEmpty(t, resp1.JSON200.Secrets)

	// verify it's cached
	time.Sleep(500 * time.Millisecond)
	helper.GetSecretsWithProxy(ctx)
	time.Sleep(500 * time.Millisecond)
	require.Contains(t, proxyCmd.Stderr(), "Cache hit")

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
		if s.SecretKey == secretName {
			assert.Equal(t, secretValue, s.SecretValue)
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

	_, helper, proxyCmd, _ := setupProxyTest(t, ctx)

	// create a test secret
	secretName := "REFRESH_TEST_" + faker.Word()
	secretValue := faker.Password()
	helper.CreateSecretWithApi(ctx, secretName, secretValue)

	// cache the secret via proxy
	slog.Info("Caching secret via proxy")
	resp1 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp1.StatusCode())

	// update the secret directly through API (not through proxy)
	slog.Info("Updating secret directly through API")
	updatedValue := "refreshed_value"
	helper.UpdateSecretWithApi(ctx, secretName, updatedValue)

	// wait for cache entry to expire and be refreshed
	slog.Info("Waiting for cache entry to expire and be refreshed (need ~15s)")
	time.Sleep(15 * time.Second)

	// verify the proxy is still running
	require.True(t, proxyCmd.IsRunning(), "Proxy should still be running")

	// fetch from proxy - should return the updated value
	slog.Info("Fetching secret after background refresh")
	resp2 := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp2.StatusCode())

	var foundUpdated bool
	for _, s := range resp2.JSON200.Secrets {
		if s.SecretKey == secretName {
			assert.Equal(t, updatedValue, s.SecretValue, "Cache should have been refreshed with new value")
			foundUpdated = true
			break
		}
	}
	require.True(t, foundUpdated, "Updated secret should be found after background refresh")
}

func TestProxy_MultipleSecrets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, _, _ := setupProxyTest(t, ctx)

	// create multiple secrets
	secrets := map[string]string{
		"MULTI_SECRET_1_" + faker.Word(): faker.Password(),
		"MULTI_SECRET_2_" + faker.Word(): faker.Password(),
		"MULTI_SECRET_3_" + faker.Word(): faker.Password(),
	}

	for name, value := range secrets {
		helper.CreateSecretWithApi(ctx, name, value)
	}

	// fetch all secrets via proxy
	slog.Info("Fetching all secrets via proxy")
	resp := helper.GetSecretsWithProxy(ctx)
	require.Equal(t, http.StatusOK, resp.StatusCode())
	require.GreaterOrEqual(t, len(resp.JSON200.Secrets), len(secrets))

	// verify all secrets are present
	for expectedName, expectedValue := range secrets {
		var found bool
		for _, s := range resp.JSON200.Secrets {
			if s.SecretKey == expectedName {
				assert.Equal(t, expectedValue, s.SecretValue)
				found = true
				break
			}
		}
		require.True(t, found, "Secret %s should be present", expectedName)
	}
}

func TestProxy_SingleSecretEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, helper, proxyCmd, _ := setupProxyTest(t, ctx)

	// create a test secret
	secretName := "SINGLE_SECRET_" + faker.Word()
	secretValue := faker.Password()
	helper.CreateSecretWithApi(ctx, secretName, secretValue)

	// fetch single secret via proxy
	slog.Info("Fetching single secret via proxy")
	resp1 := helper.GetSecretByNameWithProxy(ctx, secretName)
	require.Equal(t, http.StatusOK, resp1.StatusCode())
	require.NotNil(t, resp1.JSON200)
	assert.Equal(t, secretName, resp1.JSON200.Secret.SecretKey)
	assert.Equal(t, secretValue, resp1.JSON200.Secret.SecretValue)

	// second request should be cache hit
	time.Sleep(500 * time.Millisecond)
	resp2 := helper.GetSecretByNameWithProxy(ctx, secretName)
	require.Equal(t, http.StatusOK, resp2.StatusCode())

	time.Sleep(500 * time.Millisecond)
	require.Contains(t, proxyCmd.Stderr(), "Cache hit")
}
