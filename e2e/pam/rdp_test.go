package pam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	helpers "github.com/infisical/cli/e2e-tests/util"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	rdpUser     = "testuser"
	rdpPassword = "testpass"
)

func startRDPContainer(t *testing.T, ctx context.Context) (testcontainers.Container, int) {
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    "testdata/rdp-server",
				Dockerfile: "Dockerfile",
			},
			ExposedPorts: []string{"3389/tcp"},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.ExtraHosts = append(hc.ExtraHosts, "host.docker.internal:host-gateway")
			},
			WaitingFor: wait.ForListeningPort("3389/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := ctr.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate RDP container: %v", err)
		}
	})

	port, err := ctr.MappedPort(ctx, "3389")
	require.NoError(t, err)
	return ctr, port.Int()
}

func pamAPIRequest(t *testing.T, infra *PAMTestInfra, method, path string, body interface{}) (int, []byte) {
	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	url := infra.Infisical.ApiUrl(t) + path
	req, err := http.NewRequest(method, url, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+infra.ProvisionResult.Token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}

func createRDPPamResource(t *testing.T, ctx context.Context, infra *PAMTestInfra, name, host string, port int) uuid.UUID {
	status, respBody := pamAPIRequest(t, infra, "POST", "/api/v1/pam/resources/windows", map[string]interface{}{
		"projectId": infra.ProjectId,
		"gatewayId": infra.GatewayId,
		"name":      name,
		"connectionDetails": map[string]interface{}{
			"protocol":                "rdp",
			"hostname":                host,
			"port":                    port,
			"winrmPort":               5985,
			"useWinrmHttps":           false,
			"winrmRejectUnauthorized": false,
		},
	})
	require.Equal(t, http.StatusOK, status, "create Windows resource: %s", string(respBody))

	var result struct {
		Resource struct {
			Id uuid.UUID `json:"id"`
		} `json:"resource"`
	}
	require.NoError(t, json.Unmarshal(respBody, &result))
	slog.Info("Created Windows PAM resource", "resourceId", result.Resource.Id, "name", name)
	return result.Resource.Id
}

func createRDPPamAccount(t *testing.T, ctx context.Context, infra *PAMTestInfra, resourceId uuid.UUID, name, username, password string) {
	body := map[string]interface{}{
		"resourceId": resourceId.String(),
		"name":       name,
		"credentials": map[string]interface{}{
			"username": username,
			"password": password,
		},
		"internalMetadata": map[string]interface{}{
			"accountType": "user",
		},
	}

	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  90 * time.Second,
		Interval: 3 * time.Second,
		Condition: func() helpers.ConditionResult {
			status, respBody := pamAPIRequest(t, infra, "POST", "/api/v1/pam/accounts/windows", body)
			if status != http.StatusOK {
				slog.Warn("Windows PAM account creation returned non-200, retrying...", "status", status, "body", string(respBody))
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "Windows PAM account creation should succeed for %s", name)
	slog.Info("Created Windows PAM account", "name", name)
}

func startRDPProxy(t *testing.T, ctx context.Context, infra *PAMTestInfra, resourceName, accountName, duration string, port int) (int, *helpers.Command) {
	pamCmd := helpers.Command{
		Test:               t,
		RunMethod:          helpers.RunMethodSubprocess,
		DisableTempHomeDir: true,
		Args: []string{
			"pam", "rdp", "access",
			"--resource", resourceName,
			"--account", accountName,
			"--project-id", infra.ProjectId,
			"--duration", duration,
			"--port", fmt.Sprintf("%d", port),
			"--no-launch",
		},
		Env: map[string]string{
			"HOME":              infra.SharedHomeDir,
			"INFISICAL_API_URL": infra.Infisical.ApiUrl(t),
		},
	}
	pamCmd.Start(ctx)
	t.Cleanup(pamCmd.Stop)

	result := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Condition: func() helpers.ConditionResult {
			if strings.Contains(pamCmd.Stderr(), "RDP Proxy Session Started") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	if result != helpers.WaitSuccess {
		pamCmd.DumpOutput()
	}
	require.Equal(t, helpers.WaitSuccess, result, "RDP proxy should start successfully")

	return port, &pamCmd
}

func findFreeRDPBinary(t *testing.T) string {
	for _, name := range []string{"xfreerdp3", "xfreerdp"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Skip("xfreerdp not found; install freerdp2-x11 or freerdp3-x11")
	return ""
}

func connectFreeRDP(t *testing.T, ctx context.Context, binary string, proxyPort int, timeout time.Duration) error {
	timeoutMs := int(timeout.Milliseconds())
	args := []string{
		binary,
		fmt.Sprintf("/v:127.0.0.1:%d", proxyPort),
		"/u:testuser",
		"/p:",
		"/cert:ignore",
		fmt.Sprintf("/timeout:%d", timeoutMs),
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "xvfb-run", append([]string{"-a"}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xfreerdp failed (exit %v): %s", err, string(output))
	}
	return nil
}

func TestPAM_RDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	LoginUser(t, ctx, infra)

	rdpBinary := findFreeRDPBinary(t)
	resourceHost := getOutboundIP(t)

	t.Run("connection", func(t *testing.T) {
		_, rdpPort := startRDPContainer(t, ctx)
		slog.Info("RDP container started", "host", resourceHost, "port", rdpPort)

		resourceName := "rdp-connection-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-connection-account", rdpUser, rdpPassword)

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, resourceName, "rdp-connection-account", "5m", proxyPort)

		err := connectFreeRDP(t, ctx, rdpBinary, proxyPort, 30*time.Second)
		require.NoError(t, err, "FreeRDP connection through proxy should succeed")
		slog.Info("RDP connection test passed")
	})

	t.Run("bad-credentials", func(t *testing.T) {
		_, rdpPort := startRDPContainer(t, ctx)

		resourceName := "rdp-badcreds-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-badcreds-account", rdpUser, "wrong-password")

		proxyPort := helpers.GetFreePort()
		_, pamCmd := startRDPProxy(t, ctx, infra, resourceName, "rdp-badcreds-account", "5m", proxyPort)

		err := connectFreeRDP(t, ctx, rdpBinary, proxyPort, 30*time.Second)
		require.Error(t, err, "FreeRDP should fail with bad credentials")
		slog.Info("Bad credentials test passed", "error", err)

		_ = pamCmd
	})

	t.Run("unreachable-target", func(t *testing.T) {
		resourceName := "rdp-unreachable-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, "192.0.2.1", 3389)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-unreachable-account", rdpUser, rdpPassword)

		proxyPort := helpers.GetFreePort()
		_, pamCmd := startRDPProxy(t, ctx, infra, resourceName, "rdp-unreachable-account", "5m", proxyPort)

		err := connectFreeRDP(t, ctx, rdpBinary, proxyPort, 30*time.Second)
		require.Error(t, err, "FreeRDP should fail when target is unreachable")
		slog.Info("Unreachable target test passed", "error", err)

		_ = pamCmd
	})

	t.Run("reconnect", func(t *testing.T) {
		_, rdpPort := startRDPContainer(t, ctx)

		resourceName := "rdp-reconnect-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-reconnect-account", rdpUser, rdpPassword)

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, resourceName, "rdp-reconnect-account", "5m", proxyPort)

		err := connectFreeRDP(t, ctx, rdpBinary, proxyPort, 15*time.Second)
		require.NoError(t, err, "First FreeRDP connection should succeed")
		slog.Info("First RDP connection succeeded, reconnecting...")

		time.Sleep(2 * time.Second)

		err = connectFreeRDP(t, ctx, rdpBinary, proxyPort, 15*time.Second)
		require.NoError(t, err, "Second FreeRDP connection (reconnect) should succeed")
		slog.Info("Reconnect test passed")
	})

	t.Run("concurrent-connections", func(t *testing.T) {
		_, rdpPort := startRDPContainer(t, ctx)

		resourceName := "rdp-concurrent-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-concurrent-account", rdpUser, rdpPassword)

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, resourceName, "rdp-concurrent-account", "5m", proxyPort)

		const numClients = 3
		var wg sync.WaitGroup
		errs := make([]error, numClients)

		for i := 0; i < numClients; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				errs[idx] = connectFreeRDP(t, ctx, rdpBinary, proxyPort, 20*time.Second)
			}(i)
		}

		wg.Wait()
		for i, err := range errs {
			require.NoError(t, err, "concurrent RDP client %d should succeed", i)
		}
		slog.Info("All concurrent RDP connections succeeded", "numClients", numClients)
	})

	t.Run("session-duration", func(t *testing.T) {
		_, rdpPort := startRDPContainer(t, ctx)

		resourceName := "rdp-duration-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-duration-account", rdpUser, rdpPassword)

		proxyPort := helpers.GetFreePort()
		_, pamCmd := startRDPProxy(t, ctx, infra, resourceName, "rdp-duration-account", "30s", proxyPort)

		err := connectFreeRDP(t, ctx, rdpBinary, proxyPort, 15*time.Second)
		require.NoError(t, err, "Initial FreeRDP connection should succeed")

		result := helpers.WaitFor(t, helpers.WaitForOptions{
			Timeout:  60 * time.Second,
			Interval: 2 * time.Second,
			Condition: func() helpers.ConditionResult {
				if !pamCmd.IsRunning() {
					return helpers.ConditionSuccess
				}
				return helpers.ConditionWait
			},
		})
		require.Equal(t, helpers.WaitSuccess, result, "RDP proxy should terminate after session duration expires")
		slog.Info("Session duration test passed")
	})
}
