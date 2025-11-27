package relay_test

import (
	"context"
	"fmt"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
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
		apiClient, err = client.NewClientWithResponses(apiUrl, client.WithHTTPClient(&hc))
		provisioner := client.NewProvisioner(client.WithClient(apiClient))
		token, err := provisioner.Bootstrap(ctx)
		require.NoError(currentT, err)

		fmt.Printf("@@@ token = %v", token)

		/*
			hc := http.Client{}
			cc, err := client.NewClientWithResponses("http://localhost:4000", client.WithHTTPClient(&hc))
			if err != nil {
				panic(err)
			}
			fmt.Print(cc)

			res, err := cc.PostApiV1AdminSignupWithResponse(context.TODO(), client.PostApiV1AdminSignupJSONRequestBody{
				Email:     "fangpen@infisical.com",
				FirstName: "Fangpen",
				Password:  "123456",
			})
			fmt.Println(res.StatusCode())
			fmt.Println(res.JSON200.Token)
			fmt.Println(res.JSON200.Message)

			bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(res.JSON200.Token)
			if err != nil {
				panic(err)
			}
			res2, err := cc.PostApiV3AuthSelectOrganizationWithResponse(
				context.TODO(),
				client.PostApiV3AuthSelectOrganizationJSONRequestBody{
					OrganizationId: res.JSON200.Organization.Id.String(),
				},
				bearerAuth.Intercept,
			)

			fmt.Println(res2.StatusCode())
			fmt.Println(res2.JSON200.Token)

			res3, err := cc.PostApiV1AuthTokenWithResponse(context.TODO(), bearerAuth.Intercept)
			fmt.Println(res3.StatusCode())
			fmt.Println(res3.JSON200.Token)*/

		//assert.NoError(currentT, err)
		//
		//err = c.Up(context.Background())
		//assert.NoError(currentT, err)
	})

	It("works as I want", func() {
		rdb := redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})
		err := rdb.Ping(context.Background()).Err()
		//Expect("foo").To(Equal("foo"))
		Expect(err).To(BeNil())
	})
})
