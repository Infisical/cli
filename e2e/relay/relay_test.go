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

	cmdExit := EventuallyExpectStderr(t, &cmd, "Relay server started successfully", 120*time.Second, 5*time.Second)
	require.False(t, cmdExit)

	detectHeartbeat := false
	require.Eventually(t, func() bool {
		// Ensure the process is still running
		if !cmd.IsRunning() {
			exitCode := cmd.ExitCode()
			slog.Error("Command is not running as expected", "exit_code", exitCode)
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
	cmdExit = EventuallyExpectStderr(t, &cmd, "Relay is reachable by Infisical", 120*time.Second, 5*time.Second)
	assert.False(t, cmdExit)
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
	require.Eventually(t, func() bool {
		// Ensure the process is still running if it's a subprocess
		if relayCmd.RunMethod == RunMethodSubprocess && !relayCmd.IsRunning() {
			slog.Error("Command is not running as expected", "exit_code", relayCmd.Cmd().ProcessState.ExitCode())
			relayCmd.DumpOutput()
			// Somehow the relayCmd stops early, let's exit the loop early
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

	gatewayCmdExit := EventuallyExpectStderr(t, &gatewayCmd, "Successfully registered gateway and received certificates", 120*time.Second, 5*time.Second)
	require.False(t, gatewayCmdExit)

	gatewayCmdExit = EventuallyExpectStderr(t, &gatewayCmd, "Gateway is reachable by Infisical", 120*time.Second, 5*time.Second)
	assert.False(t, gatewayCmdExit)
}
