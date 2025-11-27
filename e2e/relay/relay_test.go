package relay_test

import (
	"context"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"net/http"
)

var _ = Describe("Relay", func() {
	var apiClient *client.ClientWithResponses

	BeforeEach(func() {
		ctx := context.TODO()

		stack := infisical.NewStack(infisical.WithDefaultStackFromEnv())
		compose, err := stack.ToComposeWithWaitingForService()
		require.NoError(currentT, err)
		err = compose.Up(ctx)
		require.NoError(currentT, err)
		apiUrl, err := compose.ApiUrl(ctx)
		require.NoError(currentT, err)

		hc := http.Client{}
		provisioningClient, err := client.NewClientWithResponses(apiUrl, client.WithHTTPClient(&hc))
		provisioner := client.NewProvisioner(client.WithClient(provisioningClient))
		token, err := provisioner.Bootstrap(ctx)
		require.NoError(currentT, err)

		bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(*token)
		apiClient, err = client.NewClientWithResponses(
			apiUrl,
			client.WithHTTPClient(&hc),
			client.WithRequestEditorFn(bearerAuth.Intercept),
		)
	})

	It("lists projects", func() {
		ctx := context.TODO()
		resp, err := apiClient.GetApiV1ProjectsWithResponse(ctx, &client.GetApiV1ProjectsParams{})
		Expect(err).To(BeNil())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))
	})
})
