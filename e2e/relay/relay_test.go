package relay_test

import (
	"context"
	"fmt"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
	"net/http"
)

var _ = Describe("Relay", func() {
	BeforeEach(func() {
		//ctx := context.Background()

		container := infisical.NewContainers()
		container.Up()

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

		////c, err := compose.NewDockerCompose("compose.yaml") // or multiple files: "file1.yml", "file2.yml"
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
