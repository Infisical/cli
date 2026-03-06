package pam_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPAM_SSH_ConnectToServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)

	const (
		sshUser     = "testuser"
		sshPassword = "testpass"
	)

	// Start an SSH server container (linuxserver/openssh-server)
	sshContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "linuxserver/openssh-server:latest",
			ExposedPorts: []string{"2222/tcp"},
			Env: map[string]string{
				"PASSWORD_ACCESS": "true",
				"USER_NAME":       sshUser,
				"USER_PASSWORD":   sshPassword,
				"PUID":            "1000",
				"PGID":            "1000",
			},
			WaitingFor: wait.ForListeningPort(nat.Port("2222/tcp")).WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := sshContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate SSH container: %v", err)
		}
	})

	sshPort, err := sshContainer.MappedPort(ctx, "2222")
	require.NoError(t, err)

	// Use the outbound IP so the gateway (running on the host) can reach the container
	resourceHost := getOutboundIP(t)
	slog.Info("SSH container started", "host", resourceHost, "port", sshPort.Int())

	// Create SSH PAM resource via typed API
	resourceName := "ssh-resource"
	sshResResp, err := infra.ApiClient.CreateSshPamResourceWithResponse(
		ctx,
		client.CreateSshPamResourceJSONRequestBody{
			ProjectId: uuid.MustParse(infra.ProjectId),
			GatewayId: infra.GatewayId,
			Name:      resourceName,
			ConnectionDetails: struct {
				Host string  `json:"host"`
				Port float32 `json:"port"`
			}{
				Host: resourceHost,
				Port: float32(sshPort.Int()),
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, sshResResp.StatusCode())
	resourceId := sshResResp.JSON200.Resource.Id
	slog.Info("Created SSH PAM resource", "resourceId", resourceId)

	// Create SSH PAM account (raw JSON — oapi-codegen doesn't generate helpers for the anyOf credentials union)
	accountName := "ssh-account"
	sshAcctBody, err := json.Marshal(map[string]interface{}{
		"resourceId":      resourceId.String(),
		"name":            accountName,
		"rotationEnabled": false,
		"credentials": map[string]interface{}{
			"authMethod": "password",
			"username":   sshUser,
			"password":   sshPassword,
		},
	})
	require.NoError(t, err)

	// Retry — the backend may restart after resource creation, wait for it to come back
	acctResult := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  90 * time.Second,
		Interval: 3 * time.Second,
		Condition: func() helpers.ConditionResult {
			resp, callErr := infra.ApiClient.CreateSshPamAccountWithBodyWithResponse(
				ctx, "application/json", bytes.NewReader(append([]byte(nil), sshAcctBody...)),
			)
			if callErr != nil {
				slog.Warn("SSH PAM account creation attempt failed, retrying...", "error", callErr)
				return helpers.ConditionWait
			}
			if resp.StatusCode() != http.StatusOK {
				slog.Warn("SSH PAM account creation returned non-200, retrying...", "status", resp.StatusCode(), "body", string(resp.Body))
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, acctResult, "SSH PAM account creation should succeed")
	slog.Info("Created SSH PAM account")

	// Login with provisioned admin user
	LoginUser(t, ctx, infra)

	// Create a pipe for stdin — we'll send commands to the SSH session
	stdinReader, stdinWriter := io.Pipe()

	// Run `pam ssh access` as a subprocess
	pamCmd := helpers.Command{
		Test:               t,
		RunMethod:          helpers.RunMethodSubprocess,
		DisableTempHomeDir: true,
		Stdin:              stdinReader,
		Args: []string{
			"pam", "ssh", "access",
			"--resource", resourceName,
			"--account", accountName,
			"--project-id", infra.ProjectId,
			"--duration", "5m",
		},
		Env: map[string]string{
			"HOME":              infra.SharedHomeDir,
			"INFISICAL_API_URL": infra.Infisical.ApiUrl(t),
			"PATH":              "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		},
	}
	pamCmd.Start(ctx)
	t.Cleanup(pamCmd.Stop)

	// Send echo command in a goroutine. The io.Pipe write blocks until
	// the SSH client reads, so this naturally waits for the session to be ready.
	go func() {
		fmt.Fprintln(stdinWriter, "echo hello-infisical")
	}()

	// Wait for the echo output to appear in stdout
	echoResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Timeout:          60 * time.Second,
		Interval:         1 * time.Second,
		Condition: func() helpers.ConditionResult {
			if strings.Contains(pamCmd.Stdout(), "hello-infisical") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, echoResult, "Should see echo output")

	// Close stdin to end the SSH session (EOF causes the remote shell to exit)
	stdinWriter.Close()

	// Wait for the subprocess to exit (SSH proxy calls os.Exit(0) after SSH client disconnects)
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  30 * time.Second,
		Interval: 2 * time.Second,
		Condition: func() helpers.ConditionResult {
			if !pamCmd.IsRunning() {
				if pamCmd.ExitCode() == 0 {
					slog.Info("PAM SSH access completed successfully")
					return helpers.ConditionSuccess
				}
				pamCmd.DumpOutput()
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "pam ssh access should complete successfully")
}
