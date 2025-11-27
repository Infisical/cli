package relay_test

import (
	"context"
	"github.com/go-faker/faker/v4"
	"github.com/infisical/cli/e2e-tests/packages/client"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"net/http"
)

var _ = Describe("Relay", func() {
	var infisical *InfisicalService

	BeforeEach(func() {
		infisical = NewInfisicalService()
		infisical.Up(context.Background())
	})

	It("registers a relay", func() {
		ctx := context.Background()
		c := infisical.ApiClient()

		// Create machine identity for the relay
		role := "member"
		identityResp, err := c.PostApiV1IdentitiesWithResponse(ctx, client.PostApiV1IdentitiesJSONRequestBody{
			Name:           faker.Name(),
			Role:           &role,
			OrganizationId: infisical.ProvisionResult().OrgId,
		})
		Expect(err).To(BeNil())
		Expect(identityResp.StatusCode()).To(Equal(http.StatusOK))

		// Create auth token for relay CLI
		identityId := identityResp.JSON200.Identity.Id
		tokenResp, err := c.PostApiV1AuthTokenAuthIdentitiesIdentityIdTokensWithResponse(
			ctx,
			identityId.String(),
			client.PostApiV1AuthTokenAuthIdentitiesIdentityIdTokensJSONRequestBody{},
		)
		Expect(err).To(BeNil())
		Expect(tokenResp.StatusCode()).To(Equal(http.StatusOK))

		//identityResp, err := c.GetApiV1ProjectsWithResponse(ctx, &client.GetApiV1ProjectsParams{})
		//Expect(err).To(BeNil())
		//Expect(identityResp.StatusCode()).To(Equal(http.StatusOK))
	})
})
