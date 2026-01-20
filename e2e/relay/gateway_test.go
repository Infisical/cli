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
	"sync"
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/google/uuid"
	"github.com/infisical/cli/e2e-tests/packages/client"
	openapitypes "github.com/oapi-codegen/runtime/types"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestGateway_RegistersAGateway(t *testing.T) {
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
	t.Cleanup(relayCmd.Stop)
	result := WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &relayCmd,
		ExpectedString:   "Relay is reachable by Infisical",
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
	t.Cleanup(gatewayCmd.Stop)

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

func TestGateway_RelayGatewayConnectivity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

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
	t.Cleanup(relayCmd.Stop)
	result := WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &relayCmd,
		ExpectedString:   "Relay is reachable by Infisical",
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
	t.Cleanup(gatewayCmd.Stop)
	result = WaitForStderr(t, WaitForStderrOptions{
		EnsureCmdRunning: &gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	assert.Equal(t, WaitSuccess, result)

	c := infisical.ApiClient()
	var gatewayId openapitypes.UUID
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
		ctx := t.Context()
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
		ctx := t.Context()
		// Start a Redis container using testcontainers Redis module
		redisContainer, err := tcredis.Run(ctx, "redis:8.4.0")
		require.NoError(t, err)
		t.Cleanup(func() {
			err := redisContainer.Terminate(ctx)
			if err != nil {
				t.Logf("Failed to terminate Redis container: %v", err)
			}
		})

		// Get the Redis connection string
		connectionString, err := redisContainer.ConnectionString(ctx)
		require.NoError(t, err)
		slog.Info("Redis connection string", "connectionString", connectionString)

		// Parse connection string to get host and port for PAM resource
		redisHost, err := redisContainer.Host(ctx)
		require.NoError(t, err)
		redisPort, err := redisContainer.MappedPort(ctx, "6379")
		require.NoError(t, err)

		// Verify Redis is accessible by connecting to it
		opt, err := redis.ParseURL(connectionString)
		require.NoError(t, err)
		rdb := redis.NewClient(opt)
		t.Cleanup(func() { rdb.Close() })

		// Test connection to Redis
		pong, err := rdb.Ping(ctx).Result()
		require.NoError(t, err)
		require.Equal(t, "PONG", pong)
		slog.Info("Verified Redis is accessible", "addr", connectionString)

		// Create Redis PAM resource
		redisPortFloat := float32(redisPort.Int())
		redisPamResResp, err := c.CreateRedisPamResourceWithResponse(
			ctx,
			client.CreateRedisPamResourceJSONRequestBody{
				ProjectId: uuid.MustParse(projectId),
				GatewayId: gatewayId,
				Name:      "redis-resource",
				ConnectionDetails: struct {
					Host                  string  `json:"host"`
					Port                  float32 `json:"port"`
					SslCertificate        *string `json:"sslCertificate,omitempty"`
					SslEnabled            bool    `json:"sslEnabled"`
					SslRejectUnauthorized bool    `json:"sslRejectUnauthorized"`
				}{
					Host:                  redisHost,
					Port:                  redisPortFloat,
					SslEnabled:            false,
					SslRejectUnauthorized: false,
				},
			})
		require.NoError(t, err)
		require.Equal(t, redisPamResResp.StatusCode(), http.StatusOK)
		slog.Info("Redis PAM resource created successfully")
	})
}
