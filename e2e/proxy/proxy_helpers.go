package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	"github.com/stretchr/testify/require"
)

// ProxyTestHelper provides helper methods for proxy tests
type ProxyTestHelper struct {
	T           *testing.T
	ProxyClient client.ClientWithResponsesInterface // client pointing to proxy
	ApiClient   client.ClientWithResponsesInterface // client pointing to Infisical directly
	ProjectID   string
	Environment string
}

type Secret struct {
	SecretKey   string
	SecretValue string
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
		T:           t,
		ProxyClient: proxyClient,
		ApiClient:   apiClient,
		ProjectID:   projectID,
		Environment: "dev",
	}
}

// CreateSecretWithApi creates a secret directly through Infisical API (not through proxy)
func (h *ProxyTestHelper) CreateSecretWithApi(ctx context.Context, secret Secret) {
	secretPath := "/"
	resp, err := h.ApiClient.CreateSecretV4WithResponse(ctx, secret.SecretKey, client.CreateSecretV4JSONRequestBody{
		ProjectId:   h.ProjectID,
		Environment: h.Environment,
		SecretValue: secret.SecretValue,
		SecretPath:  &secretPath,
	})
	require.NoError(h.T, err)
	require.Equal(h.T, http.StatusOK, resp.StatusCode(), "Failed to create secret: %s", string(resp.Body))
	slog.Info("Created secret", "name", secret.SecretKey, "value", secret.SecretValue)
}

// UpdateSecretWithApi updates a secret directly through Infisical API (not through proxy)
func (h *ProxyTestHelper) UpdateSecretWithApi(ctx context.Context, secret Secret) {
	secretPath := "/"
	resp, err := h.ApiClient.UpdateSecretV4WithResponse(ctx, secret.SecretKey, client.UpdateSecretV4JSONRequestBody{
		ProjectId:   h.ProjectID,
		Environment: h.Environment,
		SecretValue: &secret.SecretValue,
		SecretPath:  &secretPath,
	})
	require.NoError(h.T, err)
	require.Equal(h.T, http.StatusOK, resp.StatusCode(), "Failed to update secret: %s", string(resp.Body))
	slog.Info("Updated secret directly", "name", secret.SecretKey, "newValue", secret.SecretValue)
}

// GetSecretsWithProxy fetches secrets through the proxy
func (h *ProxyTestHelper) GetSecretsWithProxy(ctx context.Context) *client.ListSecretsV4Response {
	secretPath := "/"
	projectID := h.ProjectID
	environment := h.Environment
	resp, err := h.ProxyClient.ListSecretsV4WithResponse(ctx, &client.ListSecretsV4Params{
		ProjectId:   &projectID,
		Environment: &environment,
		SecretPath:  &secretPath,
	})
	require.NoError(h.T, err)
	return resp
}

// GetSecretByNameWithProxy fetches a single secret through the proxy
func (h *ProxyTestHelper) GetSecretByNameWithProxy(ctx context.Context, secretName string) *client.GetSecretByNameV4Response {
	secretPath := "/"
	environment := h.Environment
	resp, err := h.ProxyClient.GetSecretByNameV4WithResponse(ctx, secretName, &client.GetSecretByNameV4Params{
		ProjectId:   h.ProjectID,
		Environment: &environment,
		SecretPath:  &secretPath,
	})
	require.NoError(h.T, err)
	return resp
}

// UpdateSecretWithProxy updates a secret through the proxy (triggers mutation purging)
func (h *ProxyTestHelper) UpdateSecretWithProxy(ctx context.Context, secret Secret) *client.UpdateSecretV4Response {
	secretPath := "/"
	resp, err := h.ProxyClient.UpdateSecretV4WithResponse(ctx, secret.SecretKey, client.UpdateSecretV4JSONRequestBody{
		ProjectId:   h.ProjectID,
		Environment: h.Environment,
		SecretPath:  &secretPath,
		SecretValue: &secret.SecretValue,
	})
	require.NoError(h.T, err)
	return resp
}

// DeleteSecretWithProxy deletes a secret through the proxy (triggers mutation purging)
func (h *ProxyTestHelper) DeleteSecretWithProxy(ctx context.Context, secretName string) *client.DeleteSecretV4Response {
	secretPath := "/"
	resp, err := h.ProxyClient.DeleteSecretV4WithResponse(ctx, secretName, client.DeleteSecretV4JSONRequestBody{
		ProjectId:   h.ProjectID,
		Environment: h.Environment,
		SecretPath:  &secretPath,
	})
	require.NoError(h.T, err)
	return resp
}

type GenerateSecretOptions struct {
	// Prefix is only used if no PresetName is provided
	Prefix string

	PresetName  string
	PresetValue string
}

func (h *ProxyTestHelper) GenerateSecret(opts GenerateSecretOptions) Secret {

	secretName := ""
	secretValue := ""

	if opts.PresetName != "" {
		secretName = opts.PresetName
	}
	if opts.PresetValue != "" {
		secretValue = opts.PresetValue
	}

	if secretName == "" {
		secretName = fmt.Sprintf("%s%s", opts.Prefix, faker.Word())
	}

	if secretValue == "" {
		secretValue = faker.Password()
	}

	return Secret{
		SecretKey:   secretName,
		SecretValue: secretValue,
	}

}
