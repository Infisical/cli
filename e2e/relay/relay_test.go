package relay_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelay_RegistersARelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infisical := NewInfisicalService().
		WithBackendEnvironment(types.NewMappingWithEquals([]string{
			// This is needed for the private ip (current host) to be accepted for the relay server
			"ALLOW_INTERNAL_IP_CONNECTIONS=true",
		})).
		Up(t, ctx)

	c := infisical.ApiClient()
	identity := infisical.CreateMachineIdentity(t, ctx, WithTokenAuth())
	require.NotNil(t, identity)

	relayName := RandomSlug(2)
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
	t.Cleanup(cmd.Stop)

	result := WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "Relay server started successfully",
	})
	require.Equal(t, WaitSuccess, result)

	result = WaitFor(t, WaitForOptions{
		EnsureCmdRunning: &cmd,
		Condition: func() ConditionResult {
			resp, err := c.GetRelaysWithResponse(ctx)
			if err != nil {
				return ConditionWait
			}
			if resp.StatusCode() != http.StatusOK {
				return ConditionWait
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
					return ConditionSuccess
				}
			}
			return ConditionWait
		},
	})
	require.Equal(t, WaitSuccess, result)

	result = WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "Relay is reachable by Infisical",
	})
	assert.Equal(t, WaitSuccess, result)
}
