package pam

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/infisical/cli/e2e-tests/packages/client"
	infisicalpkg "github.com/infisical/cli/e2e-tests/packages/infisical"
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

type SetupPAMOption func(svc *helpers.InfisicalService, extraEnv *[]string)

const RecordingBucket = "e2e-recordings"

func WithLocalStack() SetupPAMOption {
	return func(svc *helpers.InfisicalService, extraEnv *[]string) {
		infisicalpkg.WithLocalStackService(RecordingBucket)(svc.Stack)
		*extraEnv = append(*extraEnv,
			"AWS_ENDPOINT_URL=http://localstack:4566",
			fmt.Sprintf("AWS_ENDPOINT_URL_S3=http://%s:4566", infisicalpkg.LocalStackS3Endpoint))
	}
}

func SetupPAMInfra(t *testing.T, ctx context.Context, opts ...SetupPAMOption) *PAMTestInfra {
	svc := helpers.NewInfisicalService()

	var extraEnv []string
	for _, opt := range opts {
		opt(svc, &extraEnv)
	}

	env := append([]string{
		"ALLOW_INTERNAL_IP_CONNECTIONS=true",
		"NODE_ENV=test",
	}, extraEnv...)

	svc.WithBackendEnvironment(types.NewMappingWithEquals(env)).Up(t, ctx)

	c := svc.ApiClient()
	identity := svc.CreateMachineIdentity(t, ctx, helpers.WithTokenAuth())
	require.NotNil(t, identity)

	// Start relay.
	// Use the host's outbound IP so the pam access subprocess (which runs
	// on the host) can resolve the relay address returned by the backend API.
	relayHost := getOutboundIP(t)
	relayName := helpers.RandomSlug(2)
	relayCmd := &helpers.Command{
		Test: t,
		Args: []string{"relay", "start", "--domain", svc.ApiUrl(t)},
		Env: map[string]string{
			"INFISICAL_API_URL":    svc.ApiUrl(t),
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

	// Start gateway. It must be enrolled rather than started on the machine identity token:
	// the PAM session credential, end and chunk-upload routes only accept GATEWAY_ACCESS_TOKEN.
	tmpLogDir := t.TempDir()
	sessionRecordingPath := filepath.Join(tmpLogDir, "session-recording")
	require.NoError(t, os.MkdirAll(sessionRecordingPath, 0755))
	gatewayName := helpers.RandomSlug(2)
	gatewayId, enrollmentToken := CreateGatewayWithEnrollmentToken(t, ctx, svc, gatewayName)
	gatewayCmd := &helpers.Command{
		Test: t,
		Args: []string{"gateway", "start", gatewayName,
			"--enroll-method", "token",
			"--token", enrollmentToken,
			"--domain", svc.ApiUrl(t),
			fmt.Sprintf("--pam-session-recording-path=%s", sessionRecordingPath),
		},
		Env: map[string]string{
			"INFISICAL_API_URL": svc.ApiUrl(t),
		},
	}
	gatewayCmd.Start(ctx)
	t.Cleanup(gatewayCmd.Stop)
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	require.Equal(t, helpers.WaitSuccess, result)

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
		Infisical:       svc,
		ApiClient:       c,
		Identity:        identity,
		ProjectId:       projectId,
		GatewayId:       gatewayId,
		RelayCmd:        relayCmd,
		GatewayCmd:      gatewayCmd,
		ProvisionResult: svc.ProvisionResult(),
		SharedHomeDir:   sharedHomeDir,
	}
}

// postJSON sends an authenticated JSON POST and decodes the response into out. Used for endpoints
// missing from the generated client (see e2e/openapi-cfg.yaml).
func postJSON(t *testing.T, ctx context.Context, url, token string, body, out interface{}) {
	// Fastify rejects an empty body when a JSON content type is set.
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST %s: %s", url, string(respBody))
	require.NoError(t, json.Unmarshal(respBody, out))
}

// CreateGatewayWithEnrollmentToken registers a token-auth gateway and mints its enrollment token,
// which `gateway start --enroll-method token` exchanges for a gateway access token.
func CreateGatewayWithEnrollmentToken(t *testing.T, ctx context.Context, svc *helpers.InfisicalService, name string) (openapitypes.UUID, string) {
	apiUrl := svc.ApiUrl(t)
	token := svc.ProvisionResult().Token

	var gateway struct {
		Id openapitypes.UUID `json:"id"`
	}
	postJSON(t, ctx, fmt.Sprintf("%s/api/v3/gateways", apiUrl), token, map[string]interface{}{
		"name":       name,
		"authMethod": map[string]interface{}{"method": "token"},
	}, &gateway)
	require.NotZero(t, gateway.Id, "Gateway ID should be set")

	var enrollment struct {
		Token string `json:"token"`
	}
	postJSON(t, ctx,
		fmt.Sprintf("%s/api/v3/gateways/%s/token-auth/generate-enrollment-token", apiUrl, gateway.Id),
		token, nil, &enrollment,
	)
	require.NotEmpty(t, enrollment.Token, "Gateway enrollment token should be set")

	slog.Info("Created gateway", "gatewayId", gateway.Id, "name", name)
	return gateway.Id, enrollment.Token
}

// DumpOutput dumps the proxy, relay and gateway output. Proxy failures usually surface on the
// gateway side, so the `pam access` output alone rarely explains them.
func (infra *PAMTestInfra) DumpOutput(pamCmd *helpers.Command) {
	slog.Error("-------- pam access --------")
	pamCmd.DumpOutput()
	slog.Error("-------- relay --------")
	infra.RelayCmd.DumpOutput()
	slog.Error("-------- gateway --------")
	infra.GatewayCmd.DumpOutput()
}

// CreatePamAccount creates an account of the given type in the folder/template and returns its ID.
// Creation runs a connection test through the gateway, so it is retried while things settle.
func CreatePamAccount(t *testing.T, ctx context.Context, infra *PAMTestInfra, accountType, name string,
	folderId, templateId openapitypes.UUID, connectionDetails, credentials map[string]interface{}) openapitypes.UUID {
	body, err := json.Marshal(map[string]interface{}{
		"folderId":          folderId.String(),
		"templateId":        templateId.String(),
		"gatewayId":         infra.GatewayId.String(),
		"name":              name,
		"connectionDetails": connectionDetails,
		"credentials":       credentials,
	})
	require.NoError(t, err)

	url := fmt.Sprintf("%s/api/v1/pam/accounts/%s", infra.Infisical.ApiUrl(t), accountType)
	var created struct {
		Account struct {
			Id openapitypes.UUID `json:"id"`
		} `json:"account"`
	}

	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  90 * time.Second,
		Interval: 3 * time.Second,
		Condition: func() helpers.ConditionResult {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			require.NoError(t, reqErr)
			req.Header.Set("Authorization", "Bearer "+infra.ProvisionResult.Token)
			req.Header.Set("Content-Type", "application/json")

			resp, callErr := http.DefaultClient.Do(req)
			if callErr != nil {
				slog.Warn("PAM account creation failed, retrying...", "type", accountType, "error", callErr)
				return helpers.ConditionWait
			}
			defer resp.Body.Close()

			respBody, readErr := io.ReadAll(resp.Body)
			require.NoError(t, readErr)
			if resp.StatusCode != http.StatusOK {
				slog.Warn("PAM account creation returned non-200, retrying...",
					"type", accountType, "status", resp.StatusCode, "body", string(respBody))
				return helpers.ConditionWait
			}
			require.NoError(t, json.Unmarshal(respBody, &created))
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "%s PAM account creation should succeed for %s", accountType, name)
	slog.Info("Created PAM account", "type", accountType, "name", name, "accountId", created.Account.Id)
	return created.Account.Id
}

// CreatePamFolder creates a PAM folder in the project and returns its ID.
func CreatePamFolder(t *testing.T, ctx context.Context, infra *PAMTestInfra, name string) openapitypes.UUID {
	resp, err := infra.ApiClient.CreatePamFolderWithResponse(ctx, client.CreatePamFolderJSONRequestBody{
		Name: name,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "create folder: %s", string(resp.Body))
	slog.Info("Created PAM folder", "folderId", resp.JSON200.Folder.Id, "name", name)
	return resp.JSON200.Folder.Id
}

// CreatePamTemplate creates an account template of the given type, attached to the infra gateway,
// and returns its ID. Accounts created from it inherit the gateway.
func CreatePamTemplate(t *testing.T, ctx context.Context, infra *PAMTestInfra, name string, accountType client.CreatePamAccountTemplateJSONBodyType) openapitypes.UUID {
	gatewayId := infra.GatewayId
	resp, err := infra.ApiClient.CreatePamAccountTemplateWithResponse(ctx, client.CreatePamAccountTemplateJSONRequestBody{
		Name:      name,
		Type:      accountType,
		GatewayId: &gatewayId,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "create template: %s", string(resp.Body))
	slog.Info("Created PAM template", "templateId", resp.JSON200.Template.Id, "name", name, "type", accountType)
	return resp.JSON200.Template.Id
}

// CreateRecordingBucket creates the recording bucket in LocalStack. Runs from the host, where the
// vhost alias does not resolve, so it addresses LocalStack path-style on the published port.
func CreateRecordingBucket(t *testing.T, ctx context.Context, infra *PAMTestInfra) {
	container, err := infra.Infisical.Compose().ServiceContainer(ctx, "localstack")
	require.NoError(t, err)
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "4566")
	require.NoError(t, err)

	url := fmt.Sprintf("http://%s:%s/%s", host, port.Port(), RecordingBucket)
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  60 * time.Second,
		Interval: 2 * time.Second,
		Condition: func() helpers.ConditionResult {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
			require.NoError(t, reqErr)
			resp, callErr := http.DefaultClient.Do(req)
			if callErr != nil {
				slog.Warn("Bucket creation failed, retrying...", "error", callErr)
				return helpers.ConditionWait
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				slog.Warn("Bucket creation returned non-200, retrying...", "status", resp.StatusCode)
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "recording bucket creation should succeed")
	slog.Info("Created recording bucket", "bucket", RecordingBucket)
}

// CreateAwsAppConnection creates an AWS connection holding LocalStack's dummy credentials.
func CreateAwsAppConnection(t *testing.T, ctx context.Context, infra *PAMTestInfra) openapitypes.UUID {
	body, err := json.Marshal(map[string]interface{}{
		"name":   "e2e-localstack-aws",
		"method": "access-key",
		"credentials": map[string]string{
			"accessKeyId":     "test",
			"secretAccessKey": "test",
		},
	})
	require.NoError(t, err)

	resp, err := infra.ApiClient.CreateAwsAppConnectionWithBodyWithResponse(ctx, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode(), "create AWS app connection: %s", string(resp.Body))

	var result struct {
		AppConnection struct {
			Id openapitypes.UUID `json:"id"`
		} `json:"appConnection"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &result))
	slog.Info("Created AWS app connection", "connectionId", result.AppConnection.Id)
	return result.AppConnection.Id
}

// CreateRecordingPamTemplate creates a template with aws-s3 session recording, required for account
// types like Windows. Creation validates the S3 config with a real round trip against LocalStack.
func CreateRecordingPamTemplate(t *testing.T, ctx context.Context, infra *PAMTestInfra, name string,
	accountType client.CreatePamAccountTemplateJSONBodyType, connectionId openapitypes.UUID) openapitypes.UUID {
	var created struct {
		Template struct {
			Id openapitypes.UUID `json:"id"`
		} `json:"template"`
	}
	postJSON(t, ctx, fmt.Sprintf("%s/api/v1/pam/account-templates", infra.Infisical.ApiUrl(t)),
		infra.ProvisionResult.Token, map[string]interface{}{
			"name":                  name,
			"type":                  string(accountType),
			"gatewayId":             infra.GatewayId.String(),
			"recordingConnectionId": connectionId.String(),
			"settings": map[string]interface{}{
				"recordingEnabled":        true,
				"recordingStorageBackend": string(client.CreatePamAccountTemplateJSONBodySettingsRecordingStorageBackendAwsS3),
				"recordingS3Config":       map[string]interface{}{"bucket": RecordingBucket, "region": "us-east-1"},
			},
		}, &created)
	slog.Info("Created recording PAM template", "templateId", created.Template.Id, "name", name)
	return created.Template.Id
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
