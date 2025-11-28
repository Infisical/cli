package relay_test

import (
	"context"
	"github.com/Infisical/infisical-merge/packages/cmd"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/go-faker/faker/v4"
	"github.com/infisical/cli/e2e-tests/packages/client"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"net/http"
	"os"
	"strings"
)

func RandomSlug(numWords int) string {
	var words []string
	for i := 0; i < numWords; i++ {
		words = append(words, strings.ToLower(faker.Word()))
	}
	return strings.Join(words, "-")
}

var _ = Describe("Relay", func() {
	var infisical *InfisicalService

	BeforeEach(func() {
		infisical = NewInfisicalService().
			WithBackendEnvironment(types.NewMappingWithEquals([]string{
				// This is needed for the private ip (current host) to be accepted for the relay server
				"ALLOW_INTERNAL_IP_CONNECTIONS=true",
			})).
			Up(context.Background())
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

		// Update the identity to allow token auth
		identityId := identityResp.JSON200.Identity.Id
		ttl := 2592000
		useLimit := 0
		updateResp, err := c.AttachTokenAuthWithResponse(
			ctx, identityId.String(),
			client.AttachTokenAuthJSONRequestBody{
				AccessTokenTTL:          &ttl,
				AccessTokenMaxTTL:       &ttl,
				AccessTokenNumUsesLimit: &useLimit,
				AccessTokenTrustedIps: &[]struct {
					IpAddress string `json:"ipAddress"`
				}{
					{IpAddress: "0.0.0.0/0"},
					{IpAddress: "::/0"},
				},
			},
		)
		Expect(err).To(BeNil())
		Expect(updateResp.StatusCode()).To(Equal(http.StatusOK))

		// Create auth token for relay CLI
		tokenResp, err := c.PostApiV1AuthTokenAuthIdentitiesIdentityIdTokensWithResponse(
			ctx,
			identityId.String(),
			client.PostApiV1AuthTokenAuthIdentitiesIdentityIdTokensJSONRequestBody{},
		)
		Expect(err).To(BeNil())
		Expect(tokenResp.StatusCode()).To(Equal(http.StatusOK))

		t := GinkgoT()
		tempHomeDir := t.TempDir()

		os.Args = []string{"infisical", "relay", "start", "--domain", infisical.ApiUrl()}

		relayName := RandomSlug(4)
		// Need to set home in a temp dir to avoid it reading config file
		t.Setenv("HOME", tempHomeDir)
		t.Setenv("INFISICAL_API_URL", infisical.ApiUrl())
		t.Setenv("INFISICAL_RELAY_NAME", relayName)
		t.Setenv("INFISICAL_RELAY_HOST", "host.docker.internal")
		t.Setenv("INFISICAL_TOKEN", tokenResp.JSON200.AccessToken)

		err = cmd.Execute()
		Expect(err).To(BeNil())

		// TODO: we can extract commonly used helper method, like creating a machine identity with auth token, so that
		//		 we don't need to run the above manually here

		//identityResp, err := c.GetApiV1ProjectsWithResponse(ctx, &client.GetApiV1ProjectsParams{})
		//Expect(err).To(BeNil())
		//Expect(identityResp.StatusCode()).To(Equal(http.StatusOK))
	})
})
