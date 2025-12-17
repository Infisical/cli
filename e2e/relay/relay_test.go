package relay_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/go-faker/faker/v4"
	"github.com/stretchr/testify/require"
)

func RandomSlug(numWords int) string {
	var words []string
	for i := 0; i < numWords; i++ {
		words = append(words, strings.ToLower(faker.Word()))
	}
	return strings.Join(words, "-")
}

func TestRelay_RegistersARelay(t *testing.T) {
	ctx := context.Background()
	infisical := NewInfisicalService().
		WithBackendEnvironment(types.NewMappingWithEquals([]string{
			// This is needed for the private ip (current host) to be accepted for the relay server
			"ALLOW_INTERNAL_IP_CONNECTIONS=true",
		})).
		Up(t, ctx)

	c := infisical.ApiClient()
	identity := infisical.CreateMachineIdentity(t, ctx, WithTokenAuth())
	require.NotNil(t, identity)

	relayName := RandomSlug(3)
	cmd := Command{
		Test: t,
		Args: []string{"relay", "start", "--domain", infisical.ApiUrl(t)},
		Env: map[string]string{
			"INFISICAL_API_URL":    infisical.ApiUrl(t),
			"INFISICAL_RELAY_NAME": relayName,
			"INFISICAL_RELAY_HOST": "host.docker.internal",
			"INFISICAL_TOKEN":      *identity.TokenAuthToken,
		},
	}
	cmd.Start(ctx)
	defer cmd.Stop()

	require.Eventually(t, func() bool {
		// Ensure the process is still running
		cmd.AssertRunning()

		resp, err := c.GetRelaysWithResponse(ctx)
		if err != nil {
			return false
		}
		if resp.StatusCode() != http.StatusOK {
			return false
		}
		for _, relay := range *resp.JSON200 {
			slog.Info(
				"Relay info",
				"id", relay.Id,
				"name", relay.Name,
				"host", relay.Host,
				"heartbeat", relay.Heartbeat,
			)
			if relay.Name == relayName && relay.Heartbeat != nil {
				slog.Info("Confirmed relay heartbeat")
				return true
			}
		}
		return false
	}, 120*time.Second, 5*time.Second)
}
