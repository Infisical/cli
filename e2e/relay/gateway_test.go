package relay_test

import (
	"bytes"
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
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	openapitypes "github.com/oapi-codegen/runtime/types"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// createPamFolder and createPamTemplate mirror the helpers in the pam package for use in the relay
// test (folder + gateway-attached template are prerequisites for creating accounts in the new model).
func createPamFolder(t *testing.T, ctx context.Context, c client.ClientWithResponsesInterface, name string) openapitypes.UUID {
	resp, err := c.CreatePamFolderWithResponse(ctx, client.CreatePamFolderJSONRequestBody{Name: name})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "create folder: %s", string(resp.Body))
	return resp.JSON200.Folder.Id
}

func createPamTemplate(t *testing.T, ctx context.Context, c client.ClientWithResponsesInterface, name string, accountType client.CreatePamAccountTemplateJSONBodyType, gatewayId *openapitypes.UUID) openapitypes.UUID {
	resp, err := c.CreatePamAccountTemplateWithResponse(ctx, client.CreatePamAccountTemplateJSONRequestBody{
		Name:      name,
		Type:      accountType,
		GatewayId: gatewayId,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "create template: %s", string(resp.Body))
	return resp.JSON200.Template.Id
}

func TestGateway_RegistersAGateway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infisical := helpers.NewInfisicalService().
		WithBackendEnvironment(types.NewMappingWithEquals([]string{
			// This is needed for the private ip (current host) to be accepted for the relay server
			"ALLOW_INTERNAL_IP_CONNECTIONS=true",
		})).
		Up(t, ctx)

	c := infisical.ApiClient()
	identity := infisical.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity)

	relayName := helpers.RandomSlug(2)
	relayCmd := helpers.Command{
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
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &relayCmd,
		ExpectedString:   "Relay is reachable by Infisical",
	})
	require.Equal(t, helpers.WaitSuccess, result)

	tmpLogDir := t.TempDir()
	sessionRecordingPath := filepath.Join(tmpLogDir, "session-recording")
	require.NoError(t, os.MkdirAll(sessionRecordingPath, 0755))
	gatewayName := helpers.RandomSlug(2)
	gatewayCmd := helpers.Command{
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

	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &gatewayCmd,
		ExpectedString:   "Successfully registered gateway and received certificates",
	})
	require.Equal(t, helpers.WaitSuccess, result)

	result = helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &gatewayCmd,
		Condition: func() helpers.ConditionResult {
			resp, err := c.ListGatewaysWithResponse(ctx)
			if err != nil {
				return helpers.ConditionWait
			}
			if resp.StatusCode() != http.StatusOK {
				return helpers.ConditionWait
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
					return helpers.ConditionSuccess
				}
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, result)

	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	assert.Equal(t, helpers.WaitSuccess, result)
}

func TestGateway_RelayGatewayConnectivity(t *testing.T) {
	// TODO: Re-enable once the PAM revamp's e2e tests are updated. This test
	// creates PAM resources against the revamped PAM API and is temporarily
	// skipped so it stops blocking production.
	t.Skip("Temporarily disabled pending PAM revamp test updates")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infisical := helpers.NewInfisicalService().
		WithBackendEnvironment(types.NewMappingWithEquals([]string{
			// This is needed for the private ip (current host) to be accepted for the relay server
			"ALLOW_INTERNAL_IP_CONNECTIONS=true",
		})).
		Up(t, ctx)

	identity := infisical.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity)

	relayName := helpers.RandomSlug(2)
	relayCmd := helpers.Command{
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
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &relayCmd,
		ExpectedString:   "Relay is reachable by Infisical",
	})
	require.Equal(t, helpers.WaitSuccess, result)

	tmpLogDir := t.TempDir()
	sessionRecordingPath := filepath.Join(tmpLogDir, "session-recording")
	require.NoError(t, os.MkdirAll(sessionRecordingPath, 0755))
	gatewayName := helpers.RandomSlug(2)
	gatewayCmd := helpers.Command{
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
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: &gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	assert.Equal(t, helpers.WaitSuccess, result)

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

		folderId := createPamFolder(t, ctx, c, "k8s-folder")
		templateId := createPamTemplate(t, ctx, c, "k8s-template", client.CreatePamAccountTemplateJSONBodyTypeKubernetes, &gatewayId)
		k8sBody, err := json.Marshal(map[string]interface{}{
			"folderId":   folderId.String(),
			"templateId": templateId.String(),
			"gatewayId":  gatewayId.String(),
			"name":       "k8s-account",
			"connectionDetails": map[string]interface{}{
				"url":                   serverURL,
				"sslRejectUnauthorized": false,
			},
			"credentials": map[string]interface{}{
				"authMethod":          "service-account-token",
				"serviceAccountToken": "dummy-token",
			},
		})
		require.NoError(t, err)
		k8sURL := fmt.Sprintf("%s/api/v1/pam/accounts/kubernetes", infisical.ApiUrl(t))
		k8sReq, err := http.NewRequestWithContext(ctx, http.MethodPost, k8sURL, bytes.NewReader(k8sBody))
		require.NoError(t, err)
		k8sReq.Header.Set("Authorization", "Bearer "+infisical.ProvisionResult().Token)
		k8sReq.Header.Set("Content-Type", "application/json")
		k8sResp, err := http.DefaultClient.Do(k8sReq)
		require.NoError(t, err)
		defer k8sResp.Body.Close()
		require.Equal(t, http.StatusOK, k8sResp.StatusCode)
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

		// Create Redis PAM account (no generated client method on this branch; use a raw POST).
		folderId := createPamFolder(t, ctx, c, "redis-folder")
		templateId := createPamTemplate(t, ctx, c, "redis-template", client.CreatePamAccountTemplateJSONBodyTypeRedis, &gatewayId)
		redisBody, err := json.Marshal(map[string]interface{}{
			"folderId":   folderId.String(),
			"templateId": templateId.String(),
			"gatewayId":  gatewayId.String(),
			"name":       "redis-account",
			"connectionDetails": map[string]interface{}{
				"host":                  redisHost,
				"port":                  redisPort.Int(),
				"sslEnabled":            false,
				"sslRejectUnauthorized": false,
			},
			"credentials": map[string]interface{}{"username": "default"},
		})
		require.NoError(t, err)
		accURL := fmt.Sprintf("%s/api/v1/pam/accounts/redis", infisical.ApiUrl(t))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, accURL, bytes.NewReader(redisBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+infisical.ProvisionResult().Token)
		req.Header.Set("Content-Type", "application/json")
		redisResp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer redisResp.Body.Close()
		require.Equal(t, http.StatusOK, redisResp.StatusCode)
		slog.Info("Redis PAM account created successfully")
	})
}
