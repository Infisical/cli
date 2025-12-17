package relay_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/creack/pty"
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

	cmd  *exec.Cmd
	ptmx *os.File
}

func (c *Command) Start() {
	t := c.Test
	runMethod := c.RunMethod
	if runMethod == "" {
		runMethod = RunMethodSubprocess
	}

	exeFile := c.Executable
	if exeFile == "" {
		exeFile = "./infisical-merge"
	}

	env := c.Env
	if !c.DisableTempHomeDir {
		tempDir := t.TempDir()
		env["HOME"] = tempDir
	}

	switch runMethod {
	case RunMethodSubprocess:
		slog.Info("Running command %s with args %v as a sub-process", exeFile, c.Args)
		c.cmd = exec.Command(c.Executable, c.Args...)
		c.cmd.Env = make([]string, len(env))
		for k, v := range env {
			c.cmd.Env = append(c.cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
		ptmx, err := pty.Start(c.cmd)
		c.ptmx = ptmx
		require.NoError(t, err)
	}
}

func (c *Command) Stop() {
	if c.ptmx != nil {
		err := c.ptmx.Close()
		require.NoError(c.Test, err)
		c.ptmx = nil
	}
	if c.cmd != nil {
		err := c.cmd.Cancel()
		require.NoError(c.Test, err)
		err = c.cmd.Wait()
		require.NoError(c.Test, err)
		c.cmd = nil
	}
}
