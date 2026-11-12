package pam

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync/atomic"
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
	GatewayId       openapitypes.UUID
	RelayCmd        *helpers.Command
	GatewayCmd      *helpers.Command
	GatewayAPI      *GatewayAPIProxy
	ProvisionResult *client.ProvisionResult
	SharedHomeDir   string
	RecordingPath   string
}

type setupPAMConfig struct {
	backendEnv      []string
	gatewayAPIProxy bool
}

type SetupPAMOption func(svc *helpers.InfisicalService, cfg *setupPAMConfig)

const RecordingBucket = "e2e-recordings"

func WithLocalStack() SetupPAMOption {
	return func(svc *helpers.InfisicalService, cfg *setupPAMConfig) {
		infisicalpkg.WithLocalStackService(RecordingBucket)(svc.Stack)
		cfg.backendEnv = append(cfg.backendEnv,
			"AWS_ENDPOINT_URL=http://localstack:4566",
			fmt.Sprintf("AWS_ENDPOINT_URL_S3=http://%s:4566", infisicalpkg.LocalStackS3Endpoint))
	}
}

// WithGatewayAPIProxy sends the gateway's API calls through infra.GatewayAPI.
func WithGatewayAPIProxy() SetupPAMOption {
	return func(_ *helpers.InfisicalService, cfg *setupPAMConfig) {
		cfg.gatewayAPIProxy = true
	}
}

func SetupPAMInfra(t *testing.T, ctx context.Context, opts ...SetupPAMOption) *PAMTestInfra {
	svc := helpers.NewInfisicalService()

	var cfg setupPAMConfig
	for _, opt := range opts {
		opt(svc, &cfg)
	}

	env := append([]string{
		"ALLOW_INTERNAL_IP_CONNECTIONS=true",
		"NODE_ENV=test",
	}, cfg.backendEnv...)

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
	gatewayApiUrl := svc.ApiUrl(t)
	var gatewayAPI *GatewayAPIProxy
	if cfg.gatewayAPIProxy {
		gatewayAPI = startGatewayAPIProxy(t, gatewayApiUrl)
		gatewayApiUrl = gatewayAPI.URL
	}
	gatewayCmd := &helpers.Command{
		Test: t,
		Args: []string{"gateway", "start", gatewayName,
			"--enroll-method", "token",
			"--token", enrollmentToken,
			"--domain", gatewayApiUrl,
			fmt.Sprintf("--pam-session-recording-path=%s", sessionRecordingPath),
		},
		Env: map[string]string{
			"INFISICAL_API_URL": gatewayApiUrl,
		},
	}
	gatewayCmd.Start(ctx)
	t.Cleanup(gatewayCmd.Stop)
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	require.Equal(t, helpers.WaitSuccess, result)

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
		GatewayId:       gatewayId,
		RelayCmd:        relayCmd,
		GatewayCmd:      gatewayCmd,
		GatewayAPI:      gatewayAPI,
		ProvisionResult: svc.ProvisionResult(),
		SharedHomeDir:   sharedHomeDir,
		RecordingPath:   sessionRecordingPath,
	}
}

var chunkUploadPath = regexp.MustCompile(`^/api/v1/pam/sessions/[^/]+/chunks(/presigned-put)?$`)

// GatewayAPIProxy forwards the gateway's API calls to the backend and, while throttled, answers its
// recording chunk uploads the way the backend's rate limiter does.
type GatewayAPIProxy struct {
	URL       string
	throttled atomic.Bool
	rejected  atomic.Int32
}

func startGatewayAPIProxy(t *testing.T, apiUrl string) *GatewayAPIProxy {
	target, err := url.Parse(apiUrl)
	require.NoError(t, err)
	forward := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) }}

	proxy := &GatewayAPIProxy{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !proxy.throttled.Load() || r.Method != http.MethodPost || !chunkUploadPath.MatchString(r.URL.Path) {
			forward.ServeHTTP(w, r)
			return
		}
		proxy.rejected.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// The backend sends the seconds left in its one-minute window, so 60 is the longest it asks for.
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"statusCode":429,"message":"Rate limit exceeded. Please try again in 60 seconds","error":"RateLimitExceeded"}`)
	}))
	t.Cleanup(server.Close)
	proxy.URL = server.URL
	return proxy
}

func (p *GatewayAPIProxy) ThrottleChunkUploads(throttled bool) {
	p.throttled.Store(throttled)
}

func (p *GatewayAPIProxy) RejectedChunkUploads() int {
	return int(p.rejected.Load())
}

// CrashAndRestartGateway kills the gateway without letting it clean up, then starts it again the way a
// restarted host would, with its recordings and queued chunks still on disk.
func CrashAndRestartGateway(t *testing.T, ctx context.Context, infra *PAMTestInfra) {
	crashed := infra.GatewayCmd
	require.NoError(t, crashed.Cmd().Process.Kill())
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  10 * time.Second,
		Interval: 200 * time.Millisecond,
		Condition: func() helpers.ConditionResult {
			if crashed.IsRunning() {
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "gateway should exit when killed")

	// Same HOME, because enrollment saved the gateway's access token there and the token can't enroll twice.
	gatewayCmd := &helpers.Command{
		Test:               t,
		RunMethod:          helpers.RunMethodSubprocess,
		DisableTempHomeDir: true,
		Args:               crashed.Args,
		Env:                maps.Clone(crashed.Env),
	}
	gatewayCmd.Start(ctx)
	t.Cleanup(gatewayCmd.Stop)
	infra.GatewayCmd = gatewayCmd
	result = helpers.WaitForStderr(t, helpers.WaitForStderrOptions{
		EnsureCmdRunning: gatewayCmd,
		ExpectedString:   "Gateway is reachable by Infisical",
	})
	require.Equal(t, helpers.WaitSuccess, result, "gateway should come back after a restart")
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

func getRaw(ctx context.Context, url, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

func getOK(t *testing.T, ctx context.Context, url, token string) []byte {
	status, body, err := getRaw(ctx, url, token)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "GET %s: %s", url, string(body))
	return body
}

// EndPamAccess interrupts `pam access` like Ctrl+C, which ends the session through the gateway; Stop kills it and leaves the session open.
func EndPamAccess(t *testing.T, infra *PAMTestInfra, pamCmd *helpers.Command) {
	defer func() {
		if t.Failed() {
			infra.DumpOutput(pamCmd)
		}
	}()
	require.NoError(t, pamCmd.Cmd().Process.Signal(os.Interrupt))
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  60 * time.Second,
		Interval: time.Second,
		Condition: func() helpers.ConditionResult {
			if pamCmd.IsRunning() {
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "pam access should exit after an interrupt")
}

func FindPamSessionId(t *testing.T, ctx context.Context, infra *PAMTestInfra, accountName string) string {
	var list struct {
		Sessions []struct {
			Id          string `json:"id"`
			AccountName string `json:"accountName"`
		} `json:"sessions"`
	}
	body := getOK(t, ctx, fmt.Sprintf("%s/api/v1/pam/sessions?limit=100", infra.Infisical.ApiUrl(t)), infra.ProvisionResult.Token)
	require.NoError(t, json.Unmarshal(body, &list))

	var ids []string
	for _, s := range list.Sessions {
		if s.AccountName == accountName {
			ids = append(ids, s.Id)
		}
	}
	require.Len(t, ids, 1, "expected one session for account %s", accountName)
	return ids[0]
}

type RecordingChunk struct {
	ChunkIndex             int     `json:"chunkIndex"`
	StorageBackend         string  `json:"storageBackend"`
	ExternalChunkObjectKey *string `json:"externalChunkObjectKey"`
	CiphertextSha256       string  `json:"ciphertextSha256"`
	CiphertextBytes        int     `json:"ciphertextBytes"`
	Iv                     string  `json:"iv"`
	PresignedGetUrl        *string `json:"presignedGetUrl"`
}

type SessionPlayback struct {
	SessionComplete bool             `json:"sessionComplete"`
	SessionKey      string           `json:"sessionKey"`
	ProjectId       string           `json:"projectId"`
	StorageBackend  string           `json:"storageBackend"`
	Chunks          []RecordingChunk `json:"chunks"`
}

func WaitForSessionRecording(t *testing.T, ctx context.Context, infra *PAMTestInfra, sessionId string) SessionPlayback {
	return waitForPlayback(t, ctx, infra, sessionId, func(p SessionPlayback) bool {
		return p.SessionComplete && len(p.Chunks) > 0
	})
}

func waitForPlayback(t *testing.T, ctx context.Context, infra *PAMTestInfra, sessionId string, ready func(SessionPlayback) bool) SessionPlayback {
	defer func() {
		if t.Failed() {
			infra.GatewayCmd.DumpOutput()
		}
	}()
	playbackUrl := fmt.Sprintf("%s/api/v1/pam/sessions/%s/playback", infra.Infisical.ApiUrl(t), sessionId)
	var playback SessionPlayback
	var failure string
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  90 * time.Second,
		Interval: 2 * time.Second,
		Condition: func() helpers.ConditionResult {
			status, body, err := getRaw(ctx, playbackUrl, infra.ProvisionResult.Token)
			if err != nil || status != http.StatusOK {
				failure = fmt.Sprintf("GET %s: status %d, error %v: %s", playbackUrl, status, err, string(body))
				return helpers.ConditionBreakEarly
			}

			playback = SessionPlayback{}
			if err := json.Unmarshal(body, &playback); err != nil {
				failure = fmt.Sprintf("GET %s: %v", playbackUrl, err)
				return helpers.ConditionBreakEarly
			}
			slog.Info("Waiting for session recording", "sessionId", sessionId,
				"sessionComplete", playback.SessionComplete, "chunks", len(playback.Chunks))
			if ready(playback) {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, failure)
	return playback
}

func ReadSessionRecording[T any](t *testing.T, ctx context.Context, infra *PAMTestInfra, sessionId string, playback SessionPlayback) []T {
	sessionKey, err := base64.StdEncoding.DecodeString(playback.SessionKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(sessionKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	chunks := slices.Clone(playback.Chunks)
	slices.SortFunc(chunks, func(a, b RecordingChunk) int { return a.ChunkIndex - b.ChunkIndex })

	var events []T
	for i, chunk := range chunks {
		require.Equal(t, i, chunk.ChunkIndex, "recording chunks should be contiguous")

		var ciphertext []byte
		switch chunk.StorageBackend {
		case "postgres":
			ciphertext = getOK(t, ctx, fmt.Sprintf("%s/api/v1/pam/sessions/%s/chunks/%d/ciphertext",
				infra.Infisical.ApiUrl(t), sessionId, chunk.ChunkIndex), infra.ProvisionResult.Token)
		case "aws-s3":
			require.NotNil(t, chunk.ExternalChunkObjectKey, "chunk %d has no object key", chunk.ChunkIndex)
			require.Equal(t, fmt.Sprintf("%s/%s/chunk-%06d.json.enc", playback.ProjectId, sessionId, chunk.ChunkIndex),
				*chunk.ExternalChunkObjectKey)
			require.NotNil(t, chunk.PresignedGetUrl, "chunk %d has no download URL", chunk.ChunkIndex)
			ciphertext = getOK(t, ctx, *chunk.PresignedGetUrl, "")
		default:
			require.Failf(t, "unexpected storage backend", "chunk %d is stored in %q", chunk.ChunkIndex, chunk.StorageBackend)
		}

		require.Equal(t, chunk.CiphertextBytes, len(ciphertext), "chunk %d size", chunk.ChunkIndex)
		digest := sha256.Sum256(ciphertext)
		require.Equal(t, chunk.CiphertextSha256, base64.StdEncoding.EncodeToString(digest[:]), "chunk %d digest", chunk.ChunkIndex)

		iv, err := base64.StdEncoding.DecodeString(chunk.Iv)
		require.NoError(t, err)
		aad := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|v1", playback.ProjectId, sessionId, chunk.ChunkIndex, chunk.StorageBackend)))
		plaintext, err := gcm.Open(nil, iv, ciphertext, aad[:])
		require.NoError(t, err, "chunk %d should decrypt with the session key", chunk.ChunkIndex)

		var chunkEvents []T
		require.NoError(t, json.Unmarshal(plaintext, &chunkEvents), "chunk %d should hold a JSON array of events", chunk.ChunkIndex)
		events = append(events, chunkEvents...)
	}
	return events
}
