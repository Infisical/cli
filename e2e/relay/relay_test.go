package relay_test

import (
	"context"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
)

var _ = Describe("Relay", func() {
	BeforeEach(func() {
		//ctx := context.Background()

		container := infisical.NewContainers()
		container.Up()
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
