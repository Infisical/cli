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
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"github.com/Infisical/infisical-merge/packages/cmd"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/go-faker/faker/v4"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/infisical/cli/e2e-tests/packages/infisical"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
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

	// For function call method: track execution state
	functionCallCtx    context.Context
	functionCallCancel context.CancelFunc
	functionCallDone   chan struct{}
	functionCallErr    error // Store error from ExecuteContext
	functionCallErrMu  sync.Mutex
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

// resetCommandContext recursively sets the context on a command and all its children.
// This is necessary when reusing a command that was previously executed with a cancelled context.
func resetCommandContext(cmd *cobra.Command, ctx context.Context) {
	cmd.SetContext(ctx)
	for _, child := range cmd.Commands() {
		resetCommandContext(child, ctx)
	}
}

func (c *Command) Start(ctx context.Context) {
	t := c.Test
	runMethod := c.RunMethod
	if runMethod == "" {
		runMethod = getDefaultRunMethod(t)
		c.RunMethod = runMethod
	}

	tempDir := t.TempDir()

	env := c.Env
	if !c.DisableTempHomeDir {
		slog.Info("Use a temp dir HOME", "dir", tempDir)
		env["HOME"] = tempDir
	}

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

		c.cmd.Stdout = c.stdoutFile
		c.cmd.Stderr = c.stderrFile

		err := c.cmd.Start()
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

		// Create a cancellable context for tracking function call execution
		c.functionCallCtx, c.functionCallCancel = context.WithCancel(ctx)
		c.functionCallDone = make(chan struct{})

		// Recursively reset the root cmd and its children to use the new ctx
		// because in the last execution of the root cmd, the ctx was cancelled and it's
		// already assigned to the children commands.
		resetCommandContext(cmd.RootCmd, c.functionCallCtx)

		// Set RootCmd output to files
		cmd.RootCmd.SetOut(c.stdoutFile)
		cmd.RootCmd.SetErr(c.stderrFile)

		// Update log.Logger to use the testing stderr before executing
		log.Logger = log.Output(cmd.GetLoggerConfig(c.stderrFile))

		os.Args = make([]string, 0, len(c.Args)+1)
		os.Args = append(os.Args, "infisical")
		os.Args = append(os.Args, c.Args...)
		for k, v := range env {
			t.Setenv(k, v)
		}
		go func() {
			defer close(c.functionCallDone)
			err := cmd.RootCmd.ExecuteContext(c.functionCallCtx)
			if err != nil && !errors.Is(err, context.Canceled) {
				c.functionCallErrMu.Lock()
				c.functionCallErr = err
				c.functionCallErrMu.Unlock()
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
		// Cancel the context to signal the command to stop
		if c.functionCallCancel != nil {
			c.functionCallCancel()
		}
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

// ExitCode returns the exit code of the command.
// For subprocess mode: returns the process exit code (0 for success, non-zero for failure).
// For function call mode: returns 0 if no error occurred, 1 if an error occurred.
// Returns -1 if the command is still running or if the exit code cannot be determined.
func (c *Command) ExitCode() int {
	switch c.RunMethod {
	case RunMethodSubprocess:
		if c.cmd == nil || c.cmd.ProcessState == nil {
			return -1 // Still running or not started
		}
		return c.cmd.ProcessState.ExitCode()
	case RunMethodFunctionCall:
		// Check if still running
		if c.IsRunning() {
			return -1 // Still running
		}
		// Check if there was an error
		c.functionCallErrMu.Lock()
		defer c.functionCallErrMu.Unlock()
		if c.functionCallErr != nil {
			return 1 // Error occurred
		}
		return 0 // Success
	default:
		return -1
	}
}

func (c *Command) IsRunning() bool {
	switch c.RunMethod {
	case RunMethodSubprocess:
		return c.cmd != nil && c.cmd.Process != nil && c.cmd.ProcessState == nil
	case RunMethodFunctionCall:
		// Check if the function call is still running by checking:
		// 1. Context is not cancelled
		// 2. Done channel is not closed (meaning goroutine hasn't finished)
		if c.functionCallCtx == nil || c.functionCallDone == nil {
			return false
		}
		select {
		case <-c.functionCallCtx.Done():
			// Context was cancelled, command is stopping or stopped
			return false
		case <-c.functionCallDone:
			// Goroutine has completed
			return false
		default:
			// Context is not done and goroutine hasn't signaled completion
			return true
		}
	default:
		panic(fmt.Errorf("unknown RunMethod value: %s", c.RunMethod))
	}
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

// EventuallyExpectStderr waits for the command to output a specific string in stderr
// while ensuring the command is still running. Returns true if the command exited early, false otherwise.
func EventuallyExpectStderr(t *testing.T, cmd *Command, expectedString string, timeout time.Duration, interval time.Duration) bool {
	cmdExit := false
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		// Ensure the process is still running
		if !cmd.IsRunning() {
			exitCode := cmd.ExitCode()
			slog.Error("Command is not running as expected", "exit_code", exitCode)
			cmd.DumpOutput()
			// Somehow the cmd stops early, let's exit the loop early
			cmdExit = true
			// Fail the assertion to stop retrying
			assert.Fail(collect, "Command exited early")
			return
		}

		stderr := cmd.Stderr()
		if strings.Contains(stderr, expectedString) {
			slog.Info("Confirmed stderr contains expected string", "expected", expectedString)
		}
		assert.Containsf(
			collect, stderr,
			expectedString,
			"The cmd is not outputting %q in the Stderr:\n%s", expectedString, stderr,
		)
	}, timeout, interval)
	return cmdExit
}
