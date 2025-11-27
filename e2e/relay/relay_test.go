package relay_test

import (
	"context"
	"fmt"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

var _ = Describe("Relay", func() {
	BeforeEach(func() {
		//ctx := context.Background()
		stack := infisical.NewStack(infisical.WithDefaultStackFromEnv())
		dockerCompose, err := stack.ToComposeWithWaitingForService()
		assert.NoError(currentT, err)

		fmt.Println(dockerCompose)
		err = dockerCompose.Up(context.TODO())
		assert.NoError(currentT, err)

		backend, err := dockerCompose.ServiceContainer(context.TODO(), "backend")
		assert.NoError(currentT, err)

		apiPort, err := backend.MappedPort(context.TODO(), "4000")
		assert.NoError(currentT, err)

		fmt.Printf("!!!! port = %s", apiPort)

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
