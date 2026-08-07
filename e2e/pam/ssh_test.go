package pam

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	openapitypes "github.com/oapi-codegen/runtime/types"
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

func startSSHContainer(t *testing.T, ctx context.Context, env map[string]string) (testcontainers.Container, string, int) {
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
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
			WaitingFor: wait.ForAll(
				wait.ForListeningPort("22/tcp"),
				wait.ForLog("Server listening"),
			).WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := ctr.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate SSH container: %v", err)
		}
	})

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	port, err := ctr.MappedPort(ctx, "22")
	require.NoError(t, err)
	return ctr, host, port.Int()
}

// runSSHSessionAndVerify starts the SSH proxy (`pam access <folder>/<account>`), connects an SSH
// client to the local port (the gateway injects credentials, so the client uses no auth), runs a
// command, and verifies the output.
func runSSHSessionAndVerify(t *testing.T, ctx context.Context, infra *PAMTestInfra, folderName, accountName, command, expectedOutput string) {
	freePort := helpers.GetFreePort()
	pamCmd := helpers.Command{
		Test:               t,
		RunMethod:          helpers.RunMethodSubprocess,
		DisableTempHomeDir: true,
		Args: []string{
			"pam", "access", fmt.Sprintf("%s/%s", folderName, accountName),
			"--duration", "5m",
			"--port", fmt.Sprintf("%d", freePort),
		},
		Env: map[string]string{
			"HOME":              infra.SharedHomeDir,
			"INFISICAL_API_URL": infra.Infisical.ApiUrl(t),
		},
	}
	pamCmd.Start(ctx)
	t.Cleanup(pamCmd.Stop)

	startResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Condition: func() helpers.ConditionResult {
			if strings.Contains(pamCmd.Stdout(), "SSH Proxy Session Started") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	if startResult != helpers.WaitSuccess {
		infra.DumpOutput(&pamCmd)
	}
	require.Equal(t, helpers.WaitSuccess, startResult, "SSH proxy should start successfully")

	var output string
	echoResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Timeout:          60 * time.Second,
		Interval:         2 * time.Second,
		Condition: func() helpers.ConditionResult {
			sshClient, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", freePort), &ssh.ClientConfig{
				User:            sshUser,
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         5 * time.Second,
			})
			if err != nil {
				slog.Warn("SSH proxy connection attempt failed, retrying...", "error", err)
				return helpers.ConditionWait
			}
			defer sshClient.Close()

			session, err := sshClient.NewSession()
			if err != nil {
				slog.Warn("SSH session open failed, retrying...", "error", err)
				return helpers.ConditionWait
			}
			defer session.Close()

			out, err := session.CombinedOutput(command)
			if err != nil {
				slog.Warn("SSH command failed, retrying...", "error", err)
				return helpers.ConditionWait
			}
			output = string(out)
			return helpers.ConditionSuccess
		},
	})
	if echoResult != helpers.WaitSuccess {
		infra.DumpOutput(&pamCmd)
	}
	require.Equal(t, helpers.WaitSuccess, echoResult, "should run a command over the SSH proxy")
	require.Contains(t, output, expectedOutput, "command output should contain %q", expectedOutput)
}

// configureCertAuth mirrors the real setup flow: run the dashboard's `curl <setup-url> | bash` on
// the SSH server. Fetching the script also provisions the account's SSH CA. pipefail is required,
// or a failed curl leaves bash exiting 0 and the missing CA surfaces later as "ssh: no key found".
func configureCertAuth(t *testing.T, ctx context.Context, infra *PAMTestInfra, sshContainer testcontainers.Container, sshPort int, accountId openapitypes.UUID) {
	// ApiUrl returns a localhost URL which isn't reachable from inside the container.
	// Use host.docker.internal (configured via ExtraHosts in startSSHContainer) instead.
	apiURL := strings.Replace(infra.Infisical.ApiUrl(t), "localhost", "host.docker.internal", 1)
	setupURL := fmt.Sprintf("%s/api/v1/pam/accounts/%s/ssh-ca-setup", apiURL, accountId)
	curlCmd := fmt.Sprintf(
		`set -o pipefail; curl -sS --fail-with-body -H "Authorization: Bearer %s" "%s" | bash`,
		infra.ProvisionResult.Token, setupURL,
	)

	exitCode, output, err := sshContainer.Exec(ctx, []string{"bash", "-c", curlCmd})
	require.NoError(t, err)
	if exitCode != 0 {
		out, readErr := io.ReadAll(output)
		require.NoError(t, readErr)
		t.Logf("ssh-ca-setup output:\n%s", string(out))
	}
	require.Equal(t, 0, exitCode, "ssh-ca-setup script should succeed")

	// The setup script can't restart sshd in alpine (no systemctl/service).
	// Reload config by sending SIGHUP to sshd (PID 1).
	exitCode, _, err = sshContainer.Exec(ctx, []string{"kill", "-HUP", "1"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "sshd reload should succeed")

	// Confirm sshd is serving connections again after the reload with a real handshake.
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  10 * time.Second,
		Interval: 500 * time.Millisecond,
		Condition: func() helpers.ConditionResult {
			conn, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", sshPort), &ssh.ClientConfig{
				User:            sshUser,
				Auth:            []ssh.AuthMethod{ssh.Password(sshPassword)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         2 * time.Second,
			})
			if err != nil {
				return helpers.ConditionWait
			}
			conn.Close()
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "sshd should be responsive after cert auth config reload")
}

// runSSHAuthTest configures the container + PAM account for one auth method and runs the session:
//   - password:    hardcoded testuser/testpass; account gets username + password
//   - public-key:  container gets SSH_AUTHORIZED_KEY; account gets username + privateKey
//   - certificate: container configured via curl | bash (per-account ssh-ca-setup); account gets username
func runSSHAuthTest(t *testing.T, ctx context.Context, infra *PAMTestInfra, folderName string, folderId, templateId openapitypes.UUID, method string) {
	containerEnv := map[string]string{}
	accountCreds := map[string]interface{}{
		"authMethod": method,
		"username":   sshUser,
	}

	switch method {
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
		// No extra container config; cert auth is configured after account creation.
	}

	sshContainer, sshHost, sshPort := startSSHContainer(t, ctx, containerEnv)
	slog.Info("SSH container started", "method", method, "host", sshHost, "port", sshPort)

	accountName := fmt.Sprintf("ssh-%s-account", method)
	accountId := CreatePamAccount(t, ctx, infra, "ssh", accountName, folderId, templateId,
		map[string]interface{}{"host": sshHost, "port": sshPort}, accountCreds)

	if method == "certificate" {
		configureCertAuth(t, ctx, infra, sshContainer, sshPort, accountId)
	}

	marker := fmt.Sprintf("hello-%s", method)
	runSSHSessionAndVerify(t, ctx, infra, folderName, accountName, "echo "+marker, marker)
}

func TestPAM_SSH(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	LoginUser(t, ctx, infra)

	folderName := "ssh-folder"
	folderId := CreatePamFolder(t, ctx, infra, folderName)
	templateId := CreatePamTemplate(t, ctx, infra, "ssh-template", client.CreatePamAccountTemplateJSONBodyTypeSsh)

	methods := []string{"password", "public-key", "certificate"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			runSSHAuthTest(t, ctx, infra, folderName, folderId, templateId, method)
		})
	}
}
