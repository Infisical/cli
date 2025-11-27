package relay_test

import (
	"context"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	. "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"
	dockercompose "github.com/testcontainers/testcontainers-go/modules/compose"
	"log/slog"
	"net/http"
)

type InfisicalService struct {
	Stack     *infisical.Stack
	compose   infisical.Compose
	apiClient client.ClientWithResponsesInterface
}

func NewInfisicalService() *InfisicalService {
	return &InfisicalService{Stack: infisical.NewStack(infisical.WithDefaultStackFromEnv())}
}

func (h *InfisicalService) Up(ctx context.Context) {
	t := GinkgoT()
	compose, err := h.Stack.ToComposeWithWaitingForService()
	h.compose = compose
	require.NoError(t, err)
	err = h.compose.Up(ctx)
	require.NoError(t, err)
	apiUrl, err := h.compose.ApiUrl(ctx)
	require.NoError(t, err)

	slog.Info("Bootstrapping Infisical service", "apiUrl", apiUrl)
	hc := http.Client{}
	provisioningClient, err := client.NewClientWithResponses(apiUrl, client.WithHTTPClient(&hc))
	provisioner := client.NewProvisioner(client.WithClient(provisioningClient))
	token, err := provisioner.Bootstrap(ctx)
	require.NoError(t, err)
	slog.Info("Infisical service bootstrapped successfully", "token", token)

	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(*token)
	h.apiClient, err = client.NewClientWithResponses(
		apiUrl,
		client.WithHTTPClient(&hc),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		err = compose.Down(
			ctx,
			dockercompose.RemoveOrphans(true),
			dockercompose.RemoveVolumes(true),
		)
		if err != nil {
			slog.Error("Failed to clean up Infisical service", "err", err)
		}
	})
}

func (h *InfisicalService) Compose() infisical.Compose {
	return h.compose
}

func (h *InfisicalService) ApiClient() client.ClientWithResponsesInterface {
	return h.apiClient
}
