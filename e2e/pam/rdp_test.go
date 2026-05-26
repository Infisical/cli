package pam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	"github.com/jackc/pgx/v5"
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

func setupRecordingConfig(t *testing.T, ctx context.Context, infra *PAMTestInfra) {
	dbContainer, err := infra.Infisical.Compose().ServiceContainer(ctx, "db")
	require.NoError(t, err)
	dbPort, err := dbContainer.MappedPort(ctx, nat.Port("5432"))
	require.NoError(t, err)

	connStr := fmt.Sprintf("postgres://infisical:infisical@localhost:%s/infisical", dbPort.Port())
	conn, err := pgx.Connect(ctx, connStr)
	require.NoError(t, err)
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, `SET session_replication_role = 'replica'`)
	require.NoError(t, err)
	defer func() {
		_, _ = conn.Exec(ctx, `SET session_replication_role = 'origin'`)
	}()

	_, err = conn.Exec(ctx, `
		INSERT INTO pam_project_recording_configs (id, "projectId", "storageBackend", "connectionId", bucket, region)
		VALUES ($1, $2, 'aws-s3', $3, 'e2e-test-bucket', 'us-east-1')
		ON CONFLICT ("projectId") DO NOTHING`,
		uuid.New().String(), infra.ProjectId, uuid.New().String(),
	)
	require.NoError(t, err)
	slog.Info("Inserted recording config for project", "projectId", infra.ProjectId)
}

func createRDPPamResource(t *testing.T, ctx context.Context, infra *PAMTestInfra, name, host string, port int) uuid.UUID {
	gatewayId := openapitypes.UUID(infra.GatewayId)
	resp, err := infra.ApiClient.CreateWindowsPamResourceWithResponse(
		ctx,
		client.CreateWindowsPamResourceJSONRequestBody{
			ProjectId: openapitypes.UUID(uuid.MustParse(infra.ProjectId)),
			GatewayId: &gatewayId,
			Name:      name,
			ConnectionDetails: struct {
				Hostname                string                                                    `json:"hostname"`
				Port                    int                                                       `json:"port"`
				Protocol                client.CreateWindowsPamResourceJSONBodyConnectionDetailsProtocol `json:"protocol"`
				UseWinrmHttps           bool                                                      `json:"useWinrmHttps"`
				WinrmCaCert             *string                                                   `json:"winrmCaCert,omitempty"`
				WinrmPort               int                                                       `json:"winrmPort"`
				WinrmRejectUnauthorized bool                                                      `json:"winrmRejectUnauthorized"`
				WinrmTlsServerName      *string                                                   `json:"winrmTlsServerName,omitempty"`
			}{
				Hostname:                host,
				Port:                    port,
				Protocol:                client.Rdp,
				WinrmPort:               5985,
				UseWinrmHttps:           false,
				WinrmRejectUnauthorized: false,
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "create Windows resource: %s", string(resp.Body))
	slog.Info("Created Windows PAM resource", "resourceId", resp.JSON200.Resource.Id, "name", name)
	return uuid.UUID(resp.JSON200.Resource.Id)
}

func createRDPPamAccount(t *testing.T, ctx context.Context, infra *PAMTestInfra, resourceId uuid.UUID, name, username, password string) {
	body, err := json.Marshal(map[string]interface{}{
		"resourceId": resourceId.String(),
		"name":       name,
		"credentials": map[string]interface{}{
			"username": username,
			"password": password,
		},
		"internalMetadata": map[string]interface{}{
			"accountType": "user",
		},
	})
	require.NoError(t, err)

	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  90 * time.Second,
		Interval: 3 * time.Second,
		Condition: func() helpers.ConditionResult {
			resp, callErr := infra.ApiClient.CreateWindowsPamAccountWithBodyWithResponse(
				ctx, "application/json", bytes.NewReader(append([]byte(nil), body...)),
			)
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

// warmBridgeProxy pre-connects to the RDP proxy so the relay+gateway tunnel
// and Rust bridge are established, then accepts a single client connection
// and bridges the two sides. This avoids the race where freerdp's first
// BIO_read gets EAGAIN because the bridge hasn't started yet.
func warmBridgeProxy(t *testing.T, proxyPort int) (listenPort int, cleanup func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listenPort = ln.Addr().(*net.TCPAddr).Port

	// Pre-connect to the actual proxy — this triggers tunnel+bridge setup
	backConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 10*time.Second)
	require.NoError(t, err)

	// Wait for the bridge to become ready by polling until the backend
	// responds to an X.224 Connection Request.
	x224CR := []byte{
		0x03, 0x00, 0x00, 0x2b, // TPKT header (length 43)
		0x26, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
		0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20, // "Cookie: "
		0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, // "mstshash"
		0x3d, 0x74, 0x65, 0x73, 0x74, 0x0d, 0x0a, // "=test\r\n"
		0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, // RDP Nego Req (HYBRID|HYBRID_EX|SSL)
	}
	_, err = backConn.Write(x224CR)
	require.NoError(t, err)

	// Read the X.224 CC (TPKT header = 4 bytes minimum)
	backConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	hdr := make([]byte, 4)
	_, err = io.ReadFull(backConn, hdr)
	require.NoError(t, err, "bridge should respond with X.224 CC")
	backConn.SetReadDeadline(time.Time{})

	// Read the rest of the CC packet
	pktLen := int(hdr[2])<<8 | int(hdr[3])
	if pktLen > 4 {
		rest := make([]byte, pktLen-4)
		_, err = io.ReadFull(backConn, rest)
		require.NoError(t, err)
	}

	// Bridge is confirmed working. Now close this probe connection and let
	// the test connect a fresh xfreerdp through a new pre-warmed tunnel.
	backConn.Close()

	// Pre-connect again for the real xfreerdp connection
	backConn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 10*time.Second)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		client, err := ln.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		defer backConn.Close()

		go io.Copy(backConn, client)
		io.Copy(client, backConn)
	}()

	return listenPort, func() {
		ln.Close()
		backConn.Close()
		<-done
	}
}

func authOnlyFreeRDP(t *testing.T, ctx context.Context, binary string, host string, port int, user, pass string, timeout time.Duration) error {
	rdpArgs := []string{
		binary,
		fmt.Sprintf("/v:%s:%d", host, port),
		fmt.Sprintf("/u:%s", user),
		fmt.Sprintf("/p:%s", pass),
		"/cert:ignore",
		"/auth-only",
		fmt.Sprintf("/timeout:%d", int(timeout.Milliseconds())),
	}

	var args []string
	if os.Getenv("DISPLAY") == "" {
		if xvfb, err := exec.LookPath("xvfb-run"); err == nil {
			args = append([]string{xvfb, "--auto-servernum", "--"}, rdpArgs...)
		} else {
			t.Skip("no DISPLAY and xvfb-run not found")
		}
	} else {
		args = rdpArgs
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xfreerdp /auth-only failed (exit %v): %s", err, string(output))
	}
	return nil
}

func TestPAM_RDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	LoginUser(t, ctx, infra)
	setupRecordingConfig(t, ctx, infra)

	rdpBinary := findFreeRDPBinary(t)

	t.Run("direct-xrdp-connection", func(t *testing.T) {
		_, resourceHost, rdpPort := startRDPContainer(t, ctx)
		slog.Info("xrdp container started, testing direct xfreerdp connection (no proxy)", "host", resourceHost, "port", rdpPort)

		err := authOnlyFreeRDP(t, ctx, rdpBinary, resourceHost, rdpPort, rdpUser, rdpPassword, 60*time.Second)
		require.NoError(t, err, "xfreerdp /auth-only should succeed directly against xrdp container")
		slog.Info("Direct xrdp connection test passed")
	})

	t.Run("connection", func(t *testing.T) {
		_, resourceHost, rdpPort := startRDPContainer(t, ctx)
		slog.Info("RDP container started", "host", resourceHost, "port", rdpPort)

		resourceName := "rdp-connection-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-connection-account", rdpUser, rdpPassword)

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, resourceName, "rdp-connection-account", "5m", proxyPort)

		warmPort, warmCleanup := warmBridgeProxy(t, proxyPort)
		defer warmCleanup()

		err := authOnlyFreeRDP(t, ctx, rdpBinary, "127.0.0.1", warmPort, "testuser", "", 60*time.Second)
		require.NoError(t, err, "NLA authentication through proxy should succeed")
		slog.Info("RDP connection test passed")
	})

	t.Run("bad-credentials", func(t *testing.T) {
		_, resourceHost, rdpPort := startRDPContainer(t, ctx)

		resourceName := "rdp-badcreds-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-badcreds-account", rdpUser, "wrong-password")

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, resourceName, "rdp-badcreds-account", "5m", proxyPort)

		err := authOnlyFreeRDP(t, ctx, rdpBinary, "127.0.0.1", proxyPort, "testuser", "", 60*time.Second)
		require.Error(t, err, "NLA authentication should fail with bad credentials")
		slog.Info("Bad credentials test passed", "error", err)
	})

	t.Run("unreachable-target", func(t *testing.T) {
		ctr, resourceHost, rdpPort := startRDPContainer(t, ctx)

		resourceName := "rdp-unreachable-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-unreachable-account", rdpUser, rdpPassword)

		require.NoError(t, ctr.Terminate(ctx))

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, resourceName, "rdp-unreachable-account", "5m", proxyPort)

		err := authOnlyFreeRDP(t, ctx, rdpBinary, "127.0.0.1", proxyPort, "testuser", "", 60*time.Second)
		require.Error(t, err, "NLA authentication should fail when target is down")
		slog.Info("Unreachable target test passed", "error", err)
	})

	t.Run("concurrent-connections", func(t *testing.T) {
		_, resourceHost, rdpPort := startRDPContainer(t, ctx)

		resourceName := "rdp-concurrent-resource"
		resourceId := createRDPPamResource(t, ctx, infra, resourceName, resourceHost, rdpPort)
		createRDPPamAccount(t, ctx, infra, resourceId, "rdp-concurrent-account", rdpUser, rdpPassword)

		proxyPort := helpers.GetFreePort()
		startRDPProxy(t, ctx, infra, resourceName, "rdp-concurrent-account", "5m", proxyPort)

		const numClients = 3
		var wg sync.WaitGroup
		errs := make([]error, numClients)

		for i := 0; i < numClients; i++ {
			warmPort, warmCleanup := warmBridgeProxy(t, proxyPort)
			wg.Add(1)
			go func(idx, port int, cleanup func()) {
				defer wg.Done()
				defer cleanup()
				errs[idx] = authOnlyFreeRDP(t, ctx, rdpBinary, "127.0.0.1", port, "testuser", "", 60*time.Second)
			}(i, warmPort, warmCleanup)
		}

		wg.Wait()
		for i, err := range errs {
			require.NoError(t, err, "concurrent RDP client %d NLA auth should succeed", i)
		}
		slog.Info("All concurrent RDP connections succeeded", "numClients", numClients)
	})
}
