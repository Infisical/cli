package relay_test

import (
	"context"
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

	It("lists projects", func() {
		ctx := context.Background()
		c := infisical.ApiClient()

		resp, err := c.GetApiV1ProjectsWithResponse(ctx, &client.GetApiV1ProjectsParams{})
		Expect(err).To(BeNil())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))
	})
})
