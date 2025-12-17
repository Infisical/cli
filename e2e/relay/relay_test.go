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
	"github.com/stretchr/testify/assert"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	cmdExit := false
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		// Ensure the process is still running
		if !cmd.IsRunning() {
			slog.Error("Command is not running as expected", "exit_code", cmd.Cmd().ProcessState.ExitCode())
			cmd.DumpOutput()
			// Somehow the cmd stops early, let's exit the loop early
			cmdExit = true
			return
		}

		stderr := cmd.Stderr()
		assert.Containsf(
			collect, cmd.Stderr(),
			"Relay server started successfully",
			"The cmd is not outputting \"Relay server started successfully\" in the Stderr:\n%s", stderr,
		)
	}, 120*time.Second, 5*time.Second)
	require.False(t, cmdExit)

	detectHeartbeat := false
	require.Eventually(t, func() bool {
		// Ensure the process is still running
		if !cmd.IsRunning() {
			slog.Error("Command is not running as expected", "exit_code", cmd.Cmd().ProcessState.ExitCode())
			cmd.DumpOutput()
			// Somehow the cmd stops early, let's exit the loop early
			return true
		}

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
				detectHeartbeat = true
				return true
			}
		}
		return false
	}, 120*time.Second, 5*time.Second)

	assert.True(t, detectHeartbeat)
	stderr := cmd.Stderr()
	assert.Containsf(
		t, stderr,
		"Relay is reachable by Infisical",
		"The cmd is not outputting \"Relay is reachable by Infisical\" in the Stderr:\n%s", stderr,
	)
}
