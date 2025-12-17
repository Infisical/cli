package relay_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/Infisical/infisical-merge/packages/cmd"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/go-faker/faker/v4"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	"github.com/stretchr/testify/require"
	dockercompose "github.com/testcontainers/testcontainers-go/modules/compose"
)

type InfisicalService struct {
	Stack           *infisical.Stack
	compose         infisical.Compose
	apiClient       client.ClientWithResponsesInterface
	provisionResult *client.ProvisionResult
}

func NewInfisicalService() *InfisicalService {
	return &InfisicalService{Stack: infisical.NewStack(infisical.WithDefaultStackFromEnv())}
}

func (s *InfisicalService) WithBackendEnvironment(environment types.MappingWithEquals) *InfisicalService {
	backend := s.Stack.Project.Services["backend"]
	backend.Environment = backend.Environment.OverrideBy(environment)
	fmt.Print(s.Stack.Project.Services["backend"].Environment)
	return s
}

func (s *InfisicalService) Up(t *testing.T, ctx context.Context) *InfisicalService {
	compose, err := s.Stack.ToComposeWithWaitingForService()
	s.compose = compose
	require.NoError(t, err)
	err = s.compose.Up(ctx)
	require.NoError(t, err)
	apiUrl, err := s.compose.ApiUrl(ctx)
	require.NoError(t, err)

	slog.Info("Bootstrapping Infisical service", "apiUrl", apiUrl)
	hc := http.Client{}
	provisioningClient, err := client.NewClientWithResponses(apiUrl, client.WithHTTPClient(&hc))
	provisioner := client.NewProvisioner(client.WithClient(provisioningClient))
	result, err := provisioner.Bootstrap(ctx)
	require.NoError(t, err)
	slog.Info("Infisical service bootstrapped successfully", "result", result)
	s.provisionResult = result

	bearerAuth, err := securityprovider.NewSecurityProviderBearerToken(result.Token)
	s.apiClient, err = client.NewClientWithResponses(
		apiUrl,
		client.WithHTTPClient(&hc),
		client.WithRequestEditorFn(bearerAuth.Intercept),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		err = compose.Down(
			ctx,
			dockercompose.RemoveOrphans(true),
			dockercompose.RemoveVolumes(true),
		)
		if err != nil {
			slog.Error("Failed to clean up Infisical service", "err", err)
		}
	})
	return s
}

func (s *InfisicalService) Compose() infisical.Compose {
	return s.compose
}

func (s *InfisicalService) ApiClient() client.ClientWithResponsesInterface {
	return s.apiClient
}

func (s *InfisicalService) ProvisionResult() *client.ProvisionResult {
	return s.provisionResult
}

func (s *InfisicalService) ApiUrl(t *testing.T) string {
	apiUrl, err := s.compose.ApiUrl(context.Background())
	require.NoError(t, err)
	return apiUrl
}

type MachineIdentity struct {
	Id             string
	TokenAuthToken *string
}

type MachineIdentityOption func(*testing.T, context.Context, *InfisicalService, *MachineIdentity)

func (s *InfisicalService) CreateMachineIdentity(t *testing.T, ctx context.Context, options ...MachineIdentityOption) MachineIdentity {
	c := s.apiClient

	// Create machine identity for the relay
	role := "member"
	identityResp, err := c.PostApiV1IdentitiesWithResponse(ctx, client.PostApiV1IdentitiesJSONRequestBody{
		Name:           faker.Name(),
		Role:           &role,
		OrganizationId: s.provisionResult.OrgId,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, identityResp.StatusCode())

	m := MachineIdentity{Id: identityResp.JSON200.Identity.Id.String()}
	for _, o := range options {
		o(t, ctx, s, &m)
	}
	return m
}

func WithTokenAuth() MachineIdentityOption {
	return func(t *testing.T, ctx context.Context, s *InfisicalService, i *MachineIdentity) {
		c := s.apiClient

		// Update the identity to allow token auth
		ttl := 2592000
		useLimit := 0
		updateResp, err := c.AttachTokenAuthWithResponse(
			ctx,
			i.Id,
			client.AttachTokenAuthJSONRequestBody{
				AccessTokenTTL:          &ttl,
				AccessTokenMaxTTL:       &ttl,
				AccessTokenNumUsesLimit: &useLimit,
				AccessTokenTrustedIps: &[]struct {
					IpAddress string `json:"ipAddress"`
				}{
					{IpAddress: "0.0.0.0/0"},
					{IpAddress: "::/0"},
				},
			},
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, updateResp.StatusCode())

		// Create auth token for relay CLI
		tokenResp, err := c.PostApiV1AuthTokenAuthIdentitiesIdentityIdTokensWithResponse(
			ctx,
			i.Id,
			client.PostApiV1AuthTokenAuthIdentitiesIdentityIdTokensJSONRequestBody{},
		)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, updateResp.StatusCode())

		i.TokenAuthToken = &tokenResp.JSON200.AccessToken
	}
}

type RunMethod string

const (
	RunMethodSubprocess   RunMethod = "subprocess"
	RunMethodFunctionCall RunMethod = "functionCall"
)

type Command struct {
	Test               *testing.T
	Executable         string
	Args               []string
	Dir                string
	Env                map[string]string
	RunMethod          RunMethod
	DisableTempHomeDir bool

	stdoutFilePath string
	stdoutFile     *os.File
	stderrFilePath string
	stderrFile     *os.File
	cmd            *exec.Cmd
}

func (c *Command) Start(ctx context.Context) {
	t := c.Test
	runMethod := c.RunMethod
	if runMethod == "" {
		runMethod = RunMethodSubprocess
	}

	tempDir := t.TempDir()

	env := c.Env
	if !c.DisableTempHomeDir {
		slog.Info("Use a temp dir HOME", "dir", tempDir)
		env["HOME"] = tempDir
	}

	switch runMethod {
	case RunMethodSubprocess:
		exeFile := c.Executable
		if exeFile == "" {
			exeFile = "./infisical-merge"
		}

		slog.Info("Running command as a sub-process", "executable", exeFile, "args", c.Args)
		c.cmd = exec.Command(exeFile, c.Args...)
		c.cmd.Env = make([]string, 0, len(env))
		for k, v := range env {
			c.cmd.Env = append(c.cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}

		c.stdoutFilePath = path.Join(tempDir, "stdout.log")
		slog.Info("Writing stdout to temp file", "file", c.stdoutFilePath)
		stdoutFile, err := os.Create(c.stdoutFilePath)
		require.NoError(t, err)
		c.stdoutFile = stdoutFile
		c.cmd.Stdout = stdoutFile

		c.stderrFilePath = path.Join(tempDir, "stderr.log")
		slog.Info("Writing stderr to temp file", "file", c.stderrFilePath)
		stderrFile, err := os.Create(c.stderrFilePath)
		require.NoError(t, err)
		c.stderrFile = stderrFile
		c.cmd.Stderr = stderrFile

		err = c.cmd.Start()
		go func() {
			err := c.cmd.Wait()
			if err != nil {
				slog.Error("Failed to wait for cmd", "error", err)
			}
		}()
		require.NoError(t, err)
	case RunMethodFunctionCall:
		slog.Info("Running command with args by making function call", "args", c.Args)
		os.Args = make([]string, len(c.Args)+1)
		os.Args = append(os.Args, "infisical")
		os.Args = append(os.Args, c.Args...)
		for k, v := range env {
			t.Setenv(k, v)
		}
		go func() {
			if err := cmd.ExecuteContext(ctx); err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		}()
	}
}

func (c *Command) Stop() {
	if c.cmd != nil && c.cmd.Process != nil && c.cmd.ProcessState == nil {
		_ = c.cmd.Process.Kill()
	}
	if c.stdoutFile != nil {
		_ = c.stdoutFile.Close()
	}
	if c.stderrFile != nil {
		_ = c.stderrFile.Close()
	}
}

func (c *Command) Cmd() *exec.Cmd {
	return c.cmd
}

func (c *Command) IsRunning() bool {
	return c.cmd != nil && c.cmd.Process != nil && c.cmd.ProcessState == nil
}

func (c *Command) DumpOutput() {
	slog.Error(fmt.Sprintf("-------- Stdout --------:\n%s", c.Stdout()))
	slog.Error(fmt.Sprintf("-------- Stderr --------:\n%s", c.Stderr()))
}

func (c *Command) Stdout() string {
	require.NotNil(c.Test, c.stdoutFile)
	_, err := c.stdoutFile.Seek(0, io.SeekStart)
	require.NoError(c.Test, err)
	b, err := io.ReadAll(c.stdoutFile)
	require.NoError(c.Test, err)
	return string(b)
}

func (c *Command) Stderr() string {
	require.NotNil(c.Test, c.stderrFile)
	_, err := c.stderrFile.Seek(0, io.SeekStart)
	require.NoError(c.Test, err)
	b, err := io.ReadAll(c.stderrFile)
	require.NoError(c.Test, err)
	return string(b)
}
