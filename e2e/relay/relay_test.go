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
