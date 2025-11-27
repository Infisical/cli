package relay_test

import (
	"context"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	. "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"
	"net/http"
)

type ComposeService struct {
	Stack     *infisical.Stack
	Compose   infisical.Compose
	ApiClient client.ClientWithResponsesInterface
}

func NewComposeService(stack *infisical.Stack) *ComposeService {
	if stack == nil {
		stack = infisical.NewStack(infisical.WithDefaultStackFromEnv())
	}
	return &ComposeService{Stack: stack}
}

func (h *ComposeService) Up(ctx context.Context) {
	t := GinkgoT()
	compose, err := h.Stack.ToComposeWithWaitingForService()
	h.Compose = compose
	require.NoError(t, err)
	err = h.Compose.Up(ctx)
	require.NoError(t, err)
	apiUrl, err := h.Compose.ApiUrl(ctx)
	require.NoError(t, err)

	hc := http.Client{}
	provisioningClient, err := client.NewClientWithResponses(apiUrl, client.WithHTTPClient(&hc))
	provisioner := client.NewProvisioner(client.WithClient(provisioningClient))
	token, err := provisioner.Bootstrap(ctx)
	require.NoError(currentT, err)

	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(*token)
	h.ApiClient, err = client.NewClientWithResponses(
		apiUrl,
		client.WithHTTPClient(&hc),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)
}
