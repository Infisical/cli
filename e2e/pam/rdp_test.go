package pam

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	openapitypes "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	rdpUser     = "testuser"
	rdpPassword = "testpass"
)

func startRDPContainer(t *testing.T, ctx context.Context) (testcontainers.Container, string, int) {
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

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	port, err := ctr.MappedPort(ctx, "3389")
	require.NoError(t, err)
	return ctr, host, port.Int()
}

func startRDPProxy(t *testing.T, ctx context.Context, infra *PAMTestInfra, folderName, accountName, duration string, port int) (int, *helpers.Command) {
	pamCmd := helpers.Command{
		Test:               t,
		RunMethod:          helpers.RunMethodSubprocess,
		DisableTempHomeDir: true,
		Args: []string{
			"pam", "access", fmt.Sprintf("%s/%s", folderName, accountName),
			"--duration", duration,
			"--port", fmt.Sprintf("%d", port),
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
		infra.DumpOutput(&pamCmd)
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

func buildFreeRDPArgs(t *testing.T, binary string, host string, port int, user, pass string) []string {
	rdpArgs := []string{
		binary,
		fmt.Sprintf("/v:%s:%d", host, port),
		fmt.Sprintf("/u:%s", user),
		fmt.Sprintf("/p:%s", pass),
		"/cert:ignore",
	}

	if os.Getenv("DISPLAY") == "" {
		if xvfb, err := exec.LookPath("xvfb-run"); err == nil {
			return append([]string{xvfb, "--auto-servernum", "--"}, rdpArgs...)
		}
		t.Skip("no DISPLAY and xvfb-run not found")
	}
	return rdpArgs
}

func tryConnectFreeRDP(ctx context.Context, args []string, holdTime time.Duration) error {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start xfreerdp: %w", err)
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	select {
	case err := <-exited:
		return fmt.Errorf("xfreerdp exited early (exit %v): %s", err, output.String())
	case <-time.After(holdTime):
		cmd.Process.Kill()
		<-exited
		return nil
	case <-ctx.Done():
		cmd.Process.Kill()
		<-exited
		return ctx.Err()
	}
}

// Retries on transport failures from bridge startup latency.
func connectFreeRDP(t *testing.T, ctx context.Context, binary string, host string, port int, user, pass string, holdTime time.Duration) error {
	args := buildFreeRDPArgs(t, binary, host, port, user, pass)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			slog.Info("Retrying xfreerdp after transport failure", "attempt", attempt+1)
			time.Sleep(2 * time.Second)
		}
		lastErr = tryConnectFreeRDP(ctx, args, holdTime)
		if lastErr == nil {
			return nil
		}
		if !strings.Contains(lastErr.Error(), "ERRCONNECT_CONNECT_TRANSPORT_FAILED") {
			return lastErr
		}
	}
	return lastErr
}

func expectFreeRDPFailure(t *testing.T, ctx context.Context, binary string, host string, port int, user, pass string, timeout time.Duration) error {
	args := buildFreeRDPArgs(t, binary, host, port, user, pass)

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xfreerdp failed as expected (exit %v): %s", err, string(out))
	}
	return nil
}

func TestPAM_RDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Windows accounts require an S3 recording config, backed here by LocalStack.
	infra := SetupPAMInfra(t, ctx, WithLocalStack())
	LoginUser(t, ctx, infra)
	CreateRecordingBucket(t, ctx, infra)
	connectionId := CreateAwsAppConnection(t, ctx, infra)

	folderName := "rdp-folder"
	folderId := CreatePamFolder(t, ctx, infra, folderName)
	templateId := CreateRecordingPamTemplate(t, ctx, infra, "rdp-template", client.CreatePamAccountTemplateJSONBodyTypeWindows, connectionId)

	rdpBinary := findFreeRDPBinary(t)

	t.Run("connection", func(t *testing.T) {
		_, resourceHost, rdpPort := startRDPContainer(t, ctx)
		slog.Info("RDP container started", "host", resourceHost, "port", rdpPort)

		accountName := "rdp-connection-account"
		createRDPPamAccountAt(t, ctx, infra, folderId, templateId, accountName, resourceHost, rdpPort, rdpUser, rdpPassword)

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, folderName, accountName, "5m", proxyPort)

		err := connectFreeRDP(t, ctx, rdpBinary, "127.0.0.1", proxyPort, "testuser", "", 10*time.Second)
		require.NoError(t, err, "xfreerdp should connect through proxy")
		slog.Info("RDP connection test passed")
	})

	t.Run("bad-credentials", func(t *testing.T) {
		_, resourceHost, rdpPort := startRDPContainer(t, ctx)

		accountName := "rdp-badcreds-account"
		createRDPPamAccountAt(t, ctx, infra, folderId, templateId, accountName, resourceHost, rdpPort, rdpUser, "wrong-password")

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, folderName, accountName, "5m", proxyPort)

		err := expectFreeRDPFailure(t, ctx, rdpBinary, "127.0.0.1", proxyPort, "testuser", "", 60*time.Second)
		require.Error(t, err, "xfreerdp should fail with bad credentials")
		slog.Info("Bad credentials test passed", "error", err)
	})

	t.Run("unreachable-target", func(t *testing.T) {
		ctr, resourceHost, rdpPort := startRDPContainer(t, ctx)

		accountName := "rdp-unreachable-account"
		createRDPPamAccountAt(t, ctx, infra, folderId, templateId, accountName, resourceHost, rdpPort, rdpUser, rdpPassword)

		require.NoError(t, ctr.Terminate(ctx))

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, folderName, accountName, "5m", proxyPort)

		err := expectFreeRDPFailure(t, ctx, rdpBinary, "127.0.0.1", proxyPort, "testuser", "", 60*time.Second)
		require.Error(t, err, "xfreerdp should fail when target is down")
		slog.Info("Unreachable target test passed", "error", err)
	})

	t.Run("concurrent-connections", func(t *testing.T) {
		_, resourceHost, rdpPort := startRDPContainer(t, ctx)

		accountName := "rdp-concurrent-account"
		createRDPPamAccountAt(t, ctx, infra, folderId, templateId, accountName, resourceHost, rdpPort, rdpUser, rdpPassword)

		const numClients = 3
		var wg sync.WaitGroup
		errs := make([]error, numClients)

		type proxyInfo struct {
			port int
			args []string
		}
		proxies := make([]proxyInfo, numClients)
		for i := 0; i < numClients; i++ {
			port := helpers.GetFreePort()
			startRDPProxy(t, ctx, infra, folderName, accountName, "5m", port)
			proxies[i] = proxyInfo{port: port, args: buildFreeRDPArgs(t, rdpBinary, "127.0.0.1", port, "testuser", "")}
		}

		for i, p := range proxies {
			wg.Add(1)
			go func(idx int, args []string) {
				defer wg.Done()
				errs[idx] = tryConnectFreeRDP(ctx, args, 10*time.Second)
			}(i, p.args)
		}

		wg.Wait()
		for i, err := range errs {
			require.NoError(t, err, "concurrent RDP client %d should connect", i)
		}
		slog.Info("All concurrent RDP connections succeeded", "numClients", numClients)
	})
}

// createRDPPamAccountAt creates a Windows account with the given host/port.
func createRDPPamAccountAt(t *testing.T, ctx context.Context, infra *PAMTestInfra, folderId, templateId openapitypes.UUID, name, host string, port int, username, password string) {
	gatewayId := infra.GatewayId
	pw := password
	winrmPort := 5985
	body := client.CreateWindowsPamAccountJSONRequestBody{
		FolderId:   folderId,
		TemplateId: templateId,
		GatewayId:  &gatewayId,
		Name:       name,
		ConnectionDetails: struct {
			Host                    string  `json:"host"`
			Port                    int     `json:"port"`
			UseWinrmHttps           *bool   `json:"useWinrmHttps,omitempty"`
			WinrmCaCert             *string `json:"winrmCaCert,omitempty"`
			WinrmPort               *int    `json:"winrmPort,omitempty"`
			WinrmRejectUnauthorized *bool   `json:"winrmRejectUnauthorized,omitempty"`
		}{
			Host:      host,
			Port:      port,
			WinrmPort: &winrmPort,
		},
		Credentials: struct {
			Password *string `json:"password,omitempty"`
			Username string  `json:"username"`
		}{
			Username: username,
			Password: &pw,
		},
	}

	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  90 * time.Second,
		Interval: 3 * time.Second,
		Condition: func() helpers.ConditionResult {
			resp, callErr := infra.ApiClient.CreateWindowsPamAccountWithResponse(ctx, body)
			if callErr != nil {
				slog.Warn("Windows PAM account creation attempt failed, retrying...", "error", callErr)
				return helpers.ConditionWait
			}
			if resp.StatusCode() != http.StatusOK {
				slog.Warn("Windows PAM account creation returned non-200, retrying...", "status", resp.StatusCode(), "body", string(resp.Body))
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "Windows PAM account creation should succeed for %s", name)
	slog.Info("Created Windows PAM account", "name", name)
}
