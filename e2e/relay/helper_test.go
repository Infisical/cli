package relay_test

import (
	"context"
	"fmt"
	"github.com/compose-spec/compose-go/v2/types"
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
	Stack           *infisical.Stack
	compose         infisical.Compose
	apiClient       client.ClientWithResponsesInterface
	provisionResult *client.ProvisionResult
}

func NewInfisicalService() *InfisicalService {
	return &InfisicalService{Stack: infisical.NewStack(infisical.WithDefaultStackFromEnv())}
}

func (s *InfisicalService) WithBackendEnvironment(environment types.MappingWithEquals) *InfisicalService {
	backend := s.Stack.Project.Services["backend"]
	backend.Environment = backend.Environment.OverrideBy(environment)
	fmt.Print(s.Stack.Project.Services["backend"].Environment)
	return s
}

func (s *InfisicalService) Up(ctx context.Context) *InfisicalService {
	t := GinkgoT()
	compose, err := s.Stack.ToComposeWithWaitingForService()
	s.compose = compose
	require.NoError(t, err)
	err = s.compose.Up(ctx)
	require.NoError(t, err)
	apiUrl, err := s.compose.ApiUrl(ctx)
	require.NoError(t, err)

	slog.Info("Bootstrapping Infisical service", "apiUrl", apiUrl)
	hc := http.Client{}
	provisioningClient, err := client.NewClientWithResponses(apiUrl, client.WithHTTPClient(&hc))
	provisioner := client.NewProvisioner(client.WithClient(provisioningClient))
	result, err := provisioner.Bootstrap(ctx)
	require.NoError(t, err)
	slog.Info("Infisical service bootstrapped successfully", "result", result)
	s.provisionResult = result

	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(result.Token)
	s.apiClient, err = client.NewClientWithResponses(
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
	return s
}

func (s *InfisicalService) Compose() infisical.Compose {
	return s.compose
}

func (s *InfisicalService) ApiClient() client.ClientWithResponsesInterface {
	return s.apiClient
}

func (s *InfisicalService) ProvisionResult() *client.ProvisionResult {
	return s.provisionResult
}

func (s *InfisicalService) ApiUrl() string {
	apiUrl, err := s.compose.ApiUrl(context.Background())
	require.NoError(GinkgoT(), err)
	return apiUrl
}
