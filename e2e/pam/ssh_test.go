package pam_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

const (
	// Matches the hardcoded values in testdata/ssh-server/entrypoint.sh.
	sshUser     = "testuser"
	sshPassword = "testpass"
)

// sshTestCase defines a declarative SSH auth test.
// To add a new auth method: add a case to the table in TestPAM_SSH
// and handle it in runSSHAuthTest.
type sshTestCase struct {
	Name   string
	Method string // "password", "public-key", "certificate"
}

func startSSHContainer(t *testing.T, ctx context.Context, env map[string]string) (testcontainers.Container, int) {
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    "testdata/ssh-server",
				Dockerfile: "Dockerfile",
			},
			ExposedPorts: []string{"22/tcp"},
			Env:          env,
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.ExtraHosts = append(hc.ExtraHosts, "host.docker.internal:host-gateway")
			},
			WaitingFor: wait.ForListeningPort("22/tcp").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate SSH container: %v", err)
		}
	})

	port, err := container.MappedPort(ctx, "22")
	require.NoError(t, err)
	return container, port.Int()
}

func createSSHPamResource(t *testing.T, ctx context.Context, infra *PAMTestInfra, name, host string, port int) uuid.UUID {
	resp, err := infra.ApiClient.CreateSshPamResourceWithResponse(
		ctx,
		client.CreateSshPamResourceJSONRequestBody{
			ProjectId: uuid.MustParse(infra.ProjectId),
			GatewayId: infra.GatewayId,
			Name:      name,
			ConnectionDetails: struct {
				Host string  `json:"host"`
				Port float32 `json:"port"`
			}{
				Host: host,
				Port: float32(port),
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode())
	slog.Info("Created SSH PAM resource", "resourceId", resp.JSON200.Resource.Id, "name", name)
	return resp.JSON200.Resource.Id
}

func createSSHPamAccount(t *testing.T, ctx context.Context, infra *PAMTestInfra, resourceId uuid.UUID, name string, credentials map[string]interface{}) {
	body, err := json.Marshal(map[string]interface{}{
		"resourceId":      resourceId.String(),
		"name":            name,
		"rotationEnabled": false,
		"credentials":     credentials,
	})
	require.NoError(t, err)

	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  90 * time.Second,
		Interval: 3 * time.Second,
		Condition: func() helpers.ConditionResult {
			resp, callErr := infra.ApiClient.CreateSshPamAccountWithBodyWithResponse(
				ctx, "application/json", bytes.NewReader(append([]byte(nil), body...)),
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
	require.Equal(t, helpers.WaitSuccess, result, "SSH PAM account creation should succeed for %s", name)
	slog.Info("Created SSH PAM account", "name", name)
}

func runSSHSessionAndVerify(t *testing.T, ctx context.Context, infra *PAMTestInfra, resourceName, accountName, command, expectedOutput string) {
	stdinReader, stdinWriter := io.Pipe()

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
			"HOME":                infra.SharedHomeDir,
			"INFISICAL_API_URL":   infra.Infisical.ApiUrl(t),
			"INFISICAL_LOG_LEVEL": "debug",
			"PATH":                "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		},
	}
	pamCmd.Start(ctx)
	t.Cleanup(pamCmd.Stop)

	go func() {
		fmt.Fprintln(stdinWriter, command)
	}()

	echoResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Timeout:          60 * time.Second,
		Interval:         1 * time.Second,
		Condition: func() helpers.ConditionResult {
			if strings.Contains(pamCmd.Stdout(), expectedOutput) {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	if echoResult != helpers.WaitSuccess {
		pamCmd.DumpOutput()
	}
	require.Equal(t, helpers.WaitSuccess, echoResult, "Should see expected output %q", expectedOutput)

	stdinWriter.Close()

	exitResult := helpers.WaitFor(t, helpers.WaitForOptions{
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
	require.Equal(t, helpers.WaitSuccess, exitResult, "pam ssh access should complete successfully")
}

// configureCertAuth replicates the real user flow for certificate auth setup:
// the frontend shows a `curl <setup-url> | sudo bash` command that the user
// runs on their SSH server. We do the same inside the container.
// The setup script configures /etc/ssh but can't restart sshd (no systemctl in alpine),
// so we send SIGHUP to reload the config afterward.
func configureCertAuth(t *testing.T, ctx context.Context, infra *PAMTestInfra, container testcontainers.Container, sshPort int, resourceId uuid.UUID) {
	// ApiUrl returns a localhost URL which isn't reachable from inside the container.
	// Use host.docker.internal (configured via ExtraHosts in startSSHContainer) instead.
	apiURL := strings.Replace(infra.Infisical.ApiUrl(t), "localhost", "host.docker.internal", 1)
	setupURL := fmt.Sprintf("%s/api/v1/pam/resources/ssh/%s/ssh-ca-setup", apiURL, resourceId)
	curlCmd := fmt.Sprintf(`curl -sf -H "Authorization: Bearer %s" "%s" | bash`, infra.ProvisionResult.Token, setupURL)

	exitCode, _, err := container.Exec(ctx, []string{"bash", "-c", curlCmd})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "ssh-ca-setup script should succeed")

	// The setup script can't restart sshd in alpine (no systemctl/service).
	// Reload config by sending SIGHUP to sshd (PID 1).
	exitCode, _, err = container.Exec(ctx, []string{"kill", "-HUP", "1"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "sshd reload should succeed")

	// Wait for sshd to be responsive after config reload.
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  10 * time.Second,
		Interval: 500 * time.Millisecond,
		Condition: func() helpers.ConditionResult {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", sshPort), time.Second)
			if err != nil {
				return helpers.ConditionWait
			}
			conn.Close()
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "sshd should be responsive after cert auth config reload")
}

// runSSHAuthTest handles all auth-method-specific setup and runs the SSH session test.
// Each auth method configures the container and PAM account differently:
//   - password:    uses hardcoded testuser/testpass from entrypoint; account gets username + password
//   - public-key:  container gets SSH_AUTHORIZED_KEY (generated ed25519); account gets username + privateKey
//   - certificate: container configured via curl | bash (ssh-ca-setup endpoint); account gets just username
func runSSHAuthTest(t *testing.T, ctx context.Context, infra *PAMTestInfra, resourceHost string, tc sshTestCase) {
	containerEnv := map[string]string{}
	accountCreds := map[string]interface{}{
		"authMethod": tc.Method,
		"username":   sshUser,
	}

	switch tc.Method {
	case "password":
		accountCreds["password"] = sshPassword

	case "public-key":
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		sshPubKey, err := ssh.NewPublicKey(pubKey)
		require.NoError(t, err)
		containerEnv["SSH_AUTHORIZED_KEY"] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPubKey)))

		privKeyPEM, err := ssh.MarshalPrivateKey(privKey, "")
		require.NoError(t, err)
		accountCreds["privateKey"] = string(pem.EncodeToMemory(privKeyPEM))

	case "certificate":
		// No extra container config needed.
		// Cert auth is configured after resource creation via curl | bash.
	}

	container, sshPort := startSSHContainer(t, ctx, containerEnv)
	slog.Info("SSH container started", "method", tc.Method, "host", resourceHost, "port", sshPort)

	resourceName := fmt.Sprintf("ssh-%s-resource", tc.Method)
	resourceId := createSSHPamResource(t, ctx, infra, resourceName, resourceHost, sshPort)

	if tc.Method == "certificate" {
		configureCertAuth(t, ctx, infra, container, sshPort, resourceId)
	}

	accountName := fmt.Sprintf("ssh-%s-account", tc.Method)
	createSSHPamAccount(t, ctx, infra, resourceId, accountName, accountCreds)

	marker := fmt.Sprintf("hello-%s", tc.Method)
	runSSHSessionAndVerify(t, ctx, infra, resourceName, accountName, "echo "+marker, marker)
}

func TestPAM_SSH(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	LoginUser(t, ctx, infra)

	resourceHost := getOutboundIP(t)

	tests := []sshTestCase{
		{Name: "PasswordAuth", Method: "password"},
		{Name: "PublicKeyAuth", Method: "public-key"},
		{Name: "CertificateAuth", Method: "certificate"},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			runSSHAuthTest(t, ctx, infra, resourceHost, tc)
		})
	}
}
