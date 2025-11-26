package relay_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/cmd"
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

	tempHomeDir := t.TempDir()
	os.Args = []string{"infisical", "relay", "start", "--domain", infisical.ApiUrl(t)}
	relayName := RandomSlug(4)
	// Need to set home in a temp dir to avoid it reading config file
	t.Setenv("HOME", tempHomeDir)
	t.Setenv("INFISICAL_API_URL", infisical.ApiUrl(t))
	t.Setenv("INFISICAL_RELAY_NAME", relayName)
	t.Setenv("INFISICAL_RELAY_HOST", "host.docker.internal")
	t.Setenv("INFISICAL_TOKEN", *identity.TokenAuthToken)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := cmd.ExecuteContext(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}()

	require.Eventually(t, func() bool {
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
