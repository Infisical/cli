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

	_ "github.com/joho/godotenv/autoload"

	"github.com/Infisical/infisical-merge/packages/cmd"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/go-faker/faker/v4"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	dockercompose "github.com/testcontainers/testcontainers-go/modules/compose"
)

type InfisicalService struct {
	Stack           *infisical.Stack
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
	t.Cleanup(func() {
		err := s.Compose().Down(
			ctx,
			dockercompose.RemoveOrphans(true),
			dockercompose.RemoveVolumes(true),
		)
		if err != nil {
			slog.Error("Failed to clean up Infisical service", "err", err)
		}
	})

	err := s.Stack.Up(ctx)
	require.NoError(t, err)

	s.Bootstrap(ctx, t)
	return s
}

func (s *InfisicalService) Bootstrap(ctx context.Context, t *testing.T) {
	apiUrl, err := s.Stack.ApiUrl(ctx)
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
}

func (s *InfisicalService) Compose() dockercompose.ComposeStack {
	return s.Stack.Compose()
}

func (s *InfisicalService) ApiClient() client.ClientWithResponsesInterface {
	return s.apiClient
}

func (s *InfisicalService) Reset(ctx context.Context, t *testing.T) {
	err := infisical.Reset(ctx, s.Compose())
	require.NoError(t, err)
}

func (s *InfisicalService) ResetAndBootstrap(ctx context.Context, t *testing.T) {
	s.Reset(ctx, t)
	s.Bootstrap(ctx, t)
}

func (s *InfisicalService) ProvisionResult() *client.ProvisionResult {
	return s.provisionResult
}

func (s *InfisicalService) ApiUrl(t *testing.T) string {
	apiUrl, err := s.Stack.ApiUrl(context.Background())
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
	identityResp, err := c.CreateMachineIdentityWithResponse(ctx, client.CreateMachineIdentityJSONRequestBody{
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
		tokenResp, err := c.CreateTokenAuthTokenWithResponse(
			ctx,
			i.Id,
			client.CreateTokenAuthTokenJSONRequestBody{},
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

func findExecutable(t *testing.T) string {
	// First, check for INFISICAL_CLI_EXECUTABLE environment variable
	envExec := os.Getenv("INFISICAL_CLI_EXECUTABLE")
	if envExec != "" {
		if err := validateExecutable(envExec); err != nil {
			t.Fatalf("INFISICAL_CLI_EXECUTABLE is set to '%s' but the executable cannot be found or is not executable: %v\n"+
				"Please ensure the path is correct and the file has execute permissions.", envExec, err)
		}
		return envExec
	}

	// Fall back to default path
	defaultPath := "./infisical-merge"
	if err := validateExecutable(defaultPath); err != nil {
		t.Fatalf("Cannot find executable at default path '%s': %v\n"+
			"Please either:\n"+
			"  1. Build the executable and place it at './infisical-merge', or\n"+
			"  2. Set the INFISICAL_CLI_EXECUTABLE environment variable to the correct path.\n"+
			"     Example: export INFISICAL_CLI_EXECUTABLE=/path/to/infisical-merge", defaultPath, err)
	}
	return defaultPath
}

func validateExecutable(path string) error {
	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist")
		}
		return fmt.Errorf("cannot access file: %w", err)
	}

	// Check if it's a regular file (not a directory)
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not an executable file")
	}

	// Check if file is executable
	mode := info.Mode()
	if mode&0111 == 0 {
		return fmt.Errorf("file exists but is not executable (permissions: %s)", mode.String())
	}

	return nil
}

func getDefaultRunMethod(t *testing.T) RunMethod {
	envRunMethod := os.Getenv("CLI_E2E_DEFAULT_RUN_METHOD")
	if envRunMethod == "" {
		return RunMethodSubprocess
	}

	// Validate the value
	runMethod := RunMethod(envRunMethod)
	if runMethod != RunMethodSubprocess && runMethod != RunMethodFunctionCall {
		t.Fatalf("CLI_E2E_DEFAULT_RUN_METHOD is set to '%s' but is not a valid run method.\n"+
			"Valid values are: '%s' or '%s'", envRunMethod, RunMethodSubprocess, RunMethodFunctionCall)
	}

	return runMethod
}

func (c *Command) Start(ctx context.Context) {
	t := c.Test
	runMethod := c.RunMethod
	if runMethod == "" {
		runMethod = getDefaultRunMethod(t)
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
			exeFile = findExecutable(t)
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
				// Don't log "signal: killed" errors as they're expected when processes are terminated
				if err.Error() != "signal: killed" {
					slog.Error("Failed to wait for cmd", "error", err)
				}
			}
		}()
		require.NoError(t, err)
	case RunMethodFunctionCall:
		slog.Info("Running command with args by making function call", "args", c.Args)

		// Create stdout and stderr files similar to subprocess method
		c.stdoutFilePath = path.Join(tempDir, "stdout.log")
		slog.Info("Writing stdout to temp file", "file", c.stdoutFilePath)
		stdoutFile, err := os.Create(c.stdoutFilePath)
		require.NoError(t, err)
		c.stdoutFile = stdoutFile

		c.stderrFilePath = path.Join(tempDir, "stderr.log")
		slog.Info("Writing stderr to temp file", "file", c.stderrFilePath)
		stderrFile, err := os.Create(c.stderrFilePath)
		require.NoError(t, err)
		c.stderrFile = stderrFile

		// Set RootCmd output to files
		cmd.RootCmd.SetOut(stdoutFile)
		cmd.RootCmd.SetErr(stderrFile)

		// Update log.Logger to use the testing stderr before executing
		log.Logger = log.Output(cmd.GetLoggerConfig(stderrFile))

		os.Args = make([]string, 0, len(c.Args)+1)
		os.Args = append(os.Args, "infisical")
		os.Args = append(os.Args, c.Args...)
		for k, v := range env {
			t.Setenv(k, v)
		}
		go func() {
			if err := cmd.RootCmd.ExecuteContext(ctx); err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		}()
	}
}

func (c *Command) Stop() {
	if c.cmd != nil && c.cmd.Process != nil && c.cmd.ProcessState == nil {
		_ = c.cmd.Process.Kill()
	}

	// Reset logger and RootCmd outputs to safe writers before closing files
	// This prevents "file already closed" errors when the logger tries to write
	// after the files are closed
	if c.RunMethod == RunMethodFunctionCall {
		// Reset logger to use os.Stderr before closing the file
		log.Logger = log.Output(cmd.GetLoggerConfig(os.Stderr))
		// Reset RootCmd outputs to default
		cmd.RootCmd.SetOut(os.Stdout)
		cmd.RootCmd.SetErr(os.Stderr)
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
