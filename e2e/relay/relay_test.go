package relay_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	defer cmd.Stop()

	result := WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "Relay server started successfully",
	})
	require.Equal(t, WaitSuccess, result)

	detectHeartbeat := false
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
					detectHeartbeat = true
					return ConditionSuccess
				}
			}
			return ConditionWait
		},
	})
	require.Equal(t, WaitSuccess, result)

	assert.True(t, detectHeartbeat)
	result = WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &cmd,
		ExpectedString:   "Relay is reachable by Infisical",
	})
	assert.Equal(t, WaitSuccess, result)
}

func TestRelay_RegistersAGateway(t *testing.T) {
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

	relayName := RandomSlug(2)
	relayCmd := Command{
		Test: t,
		Args: []string{"relay", "start", "--domain", infisical.ApiUrl(t)},
		Env: map[string]string{
			"INFISICAL_API_URL":    infisical.ApiUrl(t),
			"INFISICAL_RELAY_NAME": relayName,
			"INFISICAL_RELAY_HOST": "host.docker.internal",
			"INFISICAL_TOKEN":      *identity.TokenAuthToken,
		},
	}
	relayCmd.Start(ctx)
	defer relayCmd.Stop()

	detectHeartbeat := false
	result := WaitFor(t, WaitForOptions{
		EnsureCmdRunning: &relayCmd,
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
					detectHeartbeat = true
					return ConditionSuccess
				}
			}
			return ConditionWait
		},
	})
	require.Equal(t, WaitSuccess, result)
	assert.True(t, detectHeartbeat)

	tmpLogDir := t.TempDir()
	sessionRecordingPath := filepath.Join(tmpLogDir, "session-recording")
	require.NoError(t, os.MkdirAll(sessionRecordingPath, 0755))
	gatewayName := RandomSlug(2)
	gatewayCmd := Command{
		Test: t,
		Args: []string{"gateway", "start",
			fmt.Sprintf("--name=%s", gatewayName),
			fmt.Sprintf("--pam-session-recording-path=%s", sessionRecordingPath),
		},
		Env: map[string]string{
			"INFISICAL_API_URL": infisical.ApiUrl(t),
			"INFISICAL_TOKEN":   *identity.TokenAuthToken,
		},
	}
	gatewayCmd.Start(ctx)
	defer gatewayCmd.Stop()

	result = WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &gatewayCmd,
		ExpectedString:   "Successfully registered gateway and received certificates",
	})
	require.Equal(t, WaitSuccess, result)

	result = WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	assert.Equal(t, WaitSuccess, result)
}
