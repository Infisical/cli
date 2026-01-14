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

	cmdExit := false
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		if cmd.RunMethod != RunMethodSubprocess {
			// For function call method, we cannot check if the subprocess if running or not,
			// also it's a bit hard to collect stderr like subprocess.
			// Ideally, we should mock it and collect them regardless
			return
		}
		// Ensure the process is still running if it's a subprocess
		if !cmd.IsRunning() {
			slog.Error("Command is not running as expected", "exit_code", cmd.Cmd().ProcessState.ExitCode())
			cmd.DumpOutput()
			// Somehow the cmd stops early, let's exit the loop early
			cmdExit = true
			return
		}

		stderr := cmd.Stderr()
		assert.Containsf(
			collect, stderr,
			"Relay server started successfully",
			"The cmd is not outputting \"Relay server started successfully\" in the Stderr:\n%s", stderr,
		)
	}, 120*time.Second, 5*time.Second)
	require.False(t, cmdExit)

	detectHeartbeat := false
	require.Eventually(t, func() bool {
		// Ensure the process is still running if it's a subprocess
		if cmd.RunMethod == RunMethodSubprocess && !cmd.IsRunning() {
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
	if cmd.RunMethod == RunMethodSubprocess {
		stderr := cmd.Stderr()
		assert.Containsf(
			t, stderr,
			"Relay is reachable by Infisical",
			"The cmd is not outputting \"Relay is reachable by Infisical\" in the Stderr:\n%s", stderr,
		)
	}
	// TODO: find a way to collect stderr for func call method and assert as well
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

	gatewayCmdExit := false
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		if gatewayCmd.RunMethod != RunMethodSubprocess {
			// For function call method, we cannot check if the subprocess if running or not,
			// also it's a bit hard to collect stderr like subprocess.
			// Ideally, we should mock it and collect them regardless
			return
		}
		// Ensure the process is still running if it's a subprocess
		if !gatewayCmd.IsRunning() {
			slog.Error("Command is not running as expected", "exit_code", gatewayCmd.Cmd().ProcessState.ExitCode())
			gatewayCmd.DumpOutput()
			// Somehow the cmd stops early, let's exit the loop early
			gatewayCmdExit = true
			return
		}

		stderr := gatewayCmd.Stderr()
		assert.Containsf(
			collect, stderr,
			"Successfully registered gateway",
			"The cmd is not outputting \"Successfully registered gateway\" in the Stderr:\n%s", stderr,
		)
	}, 120*time.Second, 5*time.Second)
	require.False(t, gatewayCmdExit)

	detectGatewayReachable := false
	require.Eventually(t, func() bool {
		// Ensure the process is still running if it's a subprocess
		if gatewayCmd.RunMethod == RunMethodSubprocess && !gatewayCmd.IsRunning() {
			slog.Error("Command is not running as expected", "exit_code", gatewayCmd.Cmd().ProcessState.ExitCode())
			gatewayCmd.DumpOutput()
			// Somehow the gatewayCmd stops early, let's exit the loop early
			return true
		}

		if gatewayCmd.RunMethod == RunMethodSubprocess {
			stderr := gatewayCmd.Stderr()
			if strings.Contains(stderr, "Gateway is reachable by Infisical") {
				slog.Info("Confirmed gateway is reachable")
				detectGatewayReachable = true
				return true
			}
		}
		return false
	}, 120*time.Second, 5*time.Second)
	assert.True(t, detectGatewayReachable)
	if gatewayCmd.RunMethod == RunMethodSubprocess {
		stderr := gatewayCmd.Stderr()
		assert.Containsf(
			t, stderr,
			"Gateway is reachable by Infisical",
			"The cmd is not outputting \"Gateway is reachable by Infisical\" in the Stderr:\n%s", stderr,
		)
	}
	// TODO: find a way to collect stderr for func call method and assert as well
}
