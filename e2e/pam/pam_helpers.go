package pam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	openapitypes "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/require"
)

// getOutboundIP returns a non-loopback IPv4 address of the host.
// This IP is reachable from both Docker containers and host processes,
// unlike "host.docker.internal" which only resolves inside Docker.
// It enumerates local interfaces instead of dialing an external address,
// so it works in air-gapped and network-restricted CI environments.
func getOutboundIP(t *testing.T) string {
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	t.Fatal("no non-loopback IPv4 address found")
	return ""
}

type PAMTestInfra struct {
	Infisical       *helpers.InfisicalService
	ApiClient       client.ClientWithResponsesInterface
	Identity        helpers.MachineIdentity
	ProjectId       string
	GatewayId       openapitypes.UUID
	RelayCmd        *helpers.Command
	GatewayCmd      *helpers.Command
	ProvisionResult *client.ProvisionResult
	SharedHomeDir   string
}

func SetupPAMInfra(t *testing.T, ctx context.Context) *PAMTestInfra {
	infisical := helpers.NewInfisicalService().
		WithBackendEnvironment(types.NewMappingWithEquals([]string{
			"ALLOW_INTERNAL_IP_CONNECTIONS=true",
			"NODE_ENV=test",
		})).
		Up(t, ctx)

	c := infisical.ApiClient()
	identity := infisical.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity)

	// Start relay.
	// Use the host's outbound IP so the pam access subprocess (which runs
	// on the host) can resolve the relay address returned by the backend API.
	relayHost := getOutboundIP(t)
	relayName := helpers.RandomSlug(2)
	relayCmd := &helpers.Command{
		Test: t,
		Args: []string{"relay", "start", "--domain", infisical.ApiUrl(t)},
		Env: map[string]string{
			"INFISICAL_API_URL":    infisical.ApiUrl(t),
			"INFISICAL_RELAY_NAME": relayName,
			"INFISICAL_RELAY_HOST": relayHost,
			"INFISICAL_TOKEN":      *identity.TokenAuthToken,
		},
	}
	relayCmd.Start(ctx)
	t.Cleanup(relayCmd.Stop)
	result := helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: relayCmd,
		ExpectedString:   "Relay is reachable by Infisical",
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// Start gateway
	tmpLogDir := t.TempDir()
	sessionRecordingPath := filepath.Join(tmpLogDir, "session-recording")
	require.NoError(t, os.MkdirAll(sessionRecordingPath, 0755))
	gatewayName := helpers.RandomSlug(2)
	gatewayCmd := &helpers.Command{
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
		EnsureCmdRunning: gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	require.Equal(t, helpers.WaitSuccess, result)

	// Find gateway ID
	var gatewayId openapitypes.UUID
	resp, err := c.ListGatewaysWithResponse(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode())
	for _, gateway := range *resp.JSON200 {
		if gateway.Name == gatewayName && gateway.Heartbeat != nil {
			gatewayId = gateway.Id
			slog.Info("Found gateway ID", "gatewayId", gatewayId)
			break
		}
	}
	require.NotZero(t, gatewayId, "Gateway ID should be set")

	// Create PAM project
	projDesc := "e2e tests for PAM"
	template := "default"
	projectType := client.Pam
	projectResp, err := c.CreateProjectWithResponse(ctx, client.CreateProjectJSONRequestBody{
		ProjectName:        "pam-e2e-tests",
		ProjectDescription: &projDesc,
		Template:           &template,
		Type:               &projectType,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, projectResp.StatusCode())
	projectId := projectResp.JSON200.Project.Id

	// Create shared HOME dir for login and pam commands.
	// Pre-seed the config to use file-based vault so the CLI never
	// attempts to access the system keychain.
	sharedHomeDir := t.TempDir()
	infisicalConfigDir := filepath.Join(sharedHomeDir, ".infisical")
	require.NoError(t, os.MkdirAll(infisicalConfigDir, 0755))
	configData, err := json.Marshal(map[string]string{
		"vaultBackendType":       "file",
		"vaultBackendPassphrase": base64.StdEncoding.EncodeToString([]byte("e2e-test-passphrase")),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(infisicalConfigDir, "infisical-config.json"),
		configData, 0644,
	))

	return &PAMTestInfra{
		Infisical:       infisical,
		ApiClient:       c,
		Identity:        identity,
		ProjectId:       projectId,
		GatewayId:       gatewayId,
		RelayCmd:        relayCmd,
		GatewayCmd:      gatewayCmd,
		ProvisionResult: infisical.ProvisionResult(),
		SharedHomeDir:   sharedHomeDir,
	}
}

func LoginUser(t *testing.T, ctx context.Context, infra *PAMTestInfra) {
	loginCmd := helpers.Command{
		Test:               t,
		RunMethod:          helpers.RunMethodSubprocess,
		DisableTempHomeDir: true,
		Args: []string{
			"login",
			"--email", infra.ProvisionResult.Email,
			"--password", infra.ProvisionResult.Password,
			"--organization-id", infra.ProvisionResult.OrgId,
			"--domain", infra.Infisical.ApiUrl(t),
		},
		Env: map[string]string{
			"HOME":              infra.SharedHomeDir,
			"INFISICAL_API_URL": infra.Infisical.ApiUrl(t),
		},
	}
	loginCmd.Start(ctx)

	// Login is a short-lived command that exits on completion.
	// Do NOT use EnsureCmdRunning — it treats any exit as failure.
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Condition: func() helpers.ConditionResult {
			if !loginCmd.IsRunning() {
				if loginCmd.ExitCode() == 0 {
					slog.Info("Login completed successfully")
					return helpers.ConditionSuccess
				}
				loginCmd.DumpOutput()
				return helpers.ConditionBreakEarly
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "Login should succeed")
}
