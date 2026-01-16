package relay_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/go-faker/faker/v4"
	"github.com/google/uuid"
	"github.com/infisical/cli/e2e-tests/packages/client"
	openapi_types "github.com/oapi-codegen/runtime/types"
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
	result := WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &relayCmd,
		ExpectedString:   "Relay server started successfully",
	})
	require.Equal(t, WaitSuccess, result)

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

	result = WaitFor(t, WaitForOptions{
		EnsureCmdRunning: &gatewayCmd,
		Condition: func() ConditionResult {
			resp, err := c.ListGatewaysWithResponse(ctx)
			if err != nil {
				return ConditionWait
			}
			if resp.StatusCode() != http.StatusOK {
				return ConditionWait
			}
			for _, gateway := range *resp.JSON200 {
				slog.Info(
					"Gateway info",
					"id", gateway.Id,
					"name", gateway.Name,
					"identityId", gateway.IdentityId,
					"heartbeat", gateway.Heartbeat,
				)
				if gateway.Name == gatewayName && gateway.Heartbeat != nil {
					slog.Info("Confirmed gateway heartbeat")
					return ConditionSuccess
				}
			}
			return ConditionWait
		},
	})
	require.Equal(t, WaitSuccess, result)

	result = WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	assert.Equal(t, WaitSuccess, result)
}

func TestRelay_RelayGatewayConnectivity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	infisical := NewInfisicalService().
		WithBackendEnvironment(types.NewMappingWithEquals([]string{
			// This is needed for the private ip (current host) to be accepted for the relay server
			"ALLOW_INTERNAL_IP_CONNECTIONS=true",
		})).
		Up(t, ctx)

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
	result := WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &relayCmd,
		ExpectedString:   "Relay server started successfully",
	})
	require.Equal(t, WaitSuccess, result)

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
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	assert.Equal(t, WaitSuccess, result)

	c := infisical.ApiClient()
	var gatewayId openapi_types.UUID
	resp, err := c.ListGatewaysWithResponse(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode())
	for _, gateway := range *resp.JSON200 {
		slog.Info(
			"Gateway info",
			"id", gateway.Id,
			"name", gateway.Name,
			"identityId", gateway.IdentityId,
			"heartbeat", gateway.Heartbeat,
		)
		if gateway.Name == gatewayName && gateway.Heartbeat != nil {
			gatewayId = gateway.Id
			slog.Info("Found gateway ID", "gatewayId", gatewayId)
			break
		}
	}
	require.NotZero(t, gatewayId, "Gateway ID should be set")

	projDesc := "e2e tests for PAM connectivity"
	template := "default"
	projectType := client.Pam
	projectResp, err := c.CreateProjectWithResponse(ctx, client.CreateProjectJSONRequestBody{
		ProjectName:        "pam-tests",
		ProjectDescription: &projDesc,
		Template:           &template,
		Type:               &projectType,
	})
	require.NoError(t, err)
	require.Equal(t, projectResp.StatusCode(), http.StatusOK)
	projectId := projectResp.JSON200.Project.Id

	t.Run("kubernetes", func(t *testing.T) {
		t.Parallel()
		// Create a mock HTTP server running on a random port in a goroutine
		// The HTTP server implements a mock /version endpoint that returns dummy data
		// and marks a variable as true when the endpoint is hit
		var versionEndpointHit bool
		var versionEndpointHitMu sync.Mutex

		// Create a listener on a random port (port 0 means OS assigns an available port)
		listener, err := net.Listen("tcp", ":0")
		require.NoError(t, err)

		server := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/version" {
					versionEndpointHitMu.Lock()
					versionEndpointHit = true
					versionEndpointHitMu.Unlock()

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					// Return dummy version data
					versionData := map[string]interface{}{
						"version": "1.0.0",
						"build":   "test-build",
					}
					json.NewEncoder(w).Encode(versionData)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}),
		}

		// Start the server in a goroutine
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				t.Errorf("Mock HTTP server error: %v", err)
			}
		}()

		// Clean up the server when the test completes
		t.Cleanup(func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
			defer shutdownCancel()
			server.Shutdown(shutdownCtx)
		})

		// Get the server URL
		serverURL := fmt.Sprintf("http://%s", listener.Addr().String())
		slog.Info("Mock HTTP server started", "url", serverURL)

		k8sPamResResp, err := c.CreateKubernetesPamResourceWithResponse(
			ctx,
			client.CreateKubernetesPamResourceJSONRequestBody{
				ProjectId: uuid.MustParse(projectId),
				GatewayId: gatewayId,
				Name:      "k8s-resource",
				ConnectionDetails: struct {
					SslCertificate        *string `json:"sslCertificate,omitempty"`
					SslRejectUnauthorized bool    `json:"sslRejectUnauthorized"`
					Url                   string  `json:"url"`
				}{
					Url:                   serverURL,
					SslRejectUnauthorized: false,
				},
			})
		require.NoError(t, err)
		require.Equal(t, k8sPamResResp.StatusCode(), http.StatusOK)
		require.True(t, versionEndpointHit)
	})

	t.Run("redis", func(t *testing.T) {
		t.Parallel()
		// TODO: Implement Redis PAM resource test
		// This should test Redis connectivity through the gateway similar to the kubernetes test above
	})
}
