package infisical

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/compose/v2/pkg/api"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

type Stack struct {
	Project *types.Project

	dockerCompose compose.ComposeStack
}

type StackOption func(*Stack)

type BackendOptions struct {
	BackendDir string
	Dockerfile string
}

func (s *Stack) Up(ctx context.Context) error {
	data, err := s.Project.MarshalYAML()
	if err != nil {
		return err
	}
	hashBytes := sha1.Sum(data)
	hashHex := hex.EncodeToString(hashBytes[:])
	uniqueName := fmt.Sprintf("infisical-cli-bdd-%s", hashHex)

	// Try to lookup for existing container with the same name
	dockerClient, err := testcontainers.NewDockerClientWithOpts(context.Background())
	if err != nil {
		return err
	}
	containers, err := dockerClient.ContainerList(ctx, container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", fmt.Sprintf("%s=%s", api.ProjectLabel, uniqueName)),
		),
	})
	if err != nil {
		return err
	}
	if len(containers) > 0 {
		runningContainers := 0
		for _, c := range containers {
			if c.State == container.StateRunning {
				runningContainers++
			}
		}
		// TODO: also maybe try to match up with services in the project YAML?
		if runningContainers == len(containers) {

			provider, err := testcontainers.NewDockerProvider(testcontainers.WithLogger(log.Default()))
			if err != nil {
				return err
			}
			s.dockerCompose = &RunningCompose{
				name:     uniqueName,
				client:   dockerClient,
				provider: provider,
			}
			// Found existing compose, reuse instead
			return nil
		}
	}

	dockerCompose, err := compose.NewDockerComposeWith(
		compose.WithStackReaders(bytes.NewReader(data)),
		compose.StackIdentifier(uniqueName),
	)
	if err != nil {
		return err
	}
	waited := dockerCompose.WaitForService(
		"backend",
		wait.ForListeningPort("4000/tcp").
			WithStartupTimeout(120*time.Second),
	)
	s.dockerCompose = waited
	return s.dockerCompose.Up(ctx)
}

func (s *Stack) Down(ctx context.Context) error {
	return s.dockerCompose.Down(ctx)
}

func (s *Stack) Compose() compose.ComposeStack {
	return s.dockerCompose
}

func (s *Stack) ApiUrl(ctx context.Context) (string, error) {
	backend, err := s.dockerCompose.ServiceContainer(ctx, "backend")
	if err != nil {
		return "", err
	}
	host, err := backend.Host(ctx)
	if err != nil {
		return "", err
	}
	port, err := backend.MappedPort(ctx, "4000")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://%s:%s", host, port.Port()), nil
}

func BackendOptionsFromEnv() BackendOptions {
	backendDir, found := os.LookupEnv("INFISICAL_BACKEND_DIR")
	if !found {
		panic("INFISICAL_BACKEND_DIR not set, in order fo the e2e tests to work, you need to set the INFISICAL_BACKEND_DIR environment variable to the path of the backend directory, e.g. /Users/your-username/code/infisical/backend")
	}
	dockerfile, found := os.LookupEnv("INFISICAL_BACKEND_DOCKERFILE")
	if !found {
		dockerfile = "Dockerfile.dev.fips"
	}
	return BackendOptions{
		BackendDir: backendDir,
		Dockerfile: dockerfile,
	}
}

func NewStack(options ...StackOption) *Stack {
	s := &Stack{
		Project: &types.Project{},
	}
	for _, o := range options {
		o(s)
	}
	return s
}

func WithDbService() StackOption {
	return func(s *Stack) {
		if s.Project.Services == nil {
			s.Project.Services = types.Services{}
		}
		s.Project.Services["db"] = types.ServiceConfig{
			Image: "postgres:14-alpine",
			Ports: []types.ServicePortConfig{{Published: "", Target: 5432}},
			Environment: types.NewMappingWithEquals([]string{
				"POSTGRES_DB=infisical",
				"POSTGRES_USER=infisical",
				"POSTGRES_PASSWORD=infisical",
			}),
		}
	}
}

func WithRedisService() StackOption {
	return func(s *Stack) {
		if s.Project.Services == nil {
			s.Project.Services = types.Services{}
		}
		s.Project.Services["redis"] = types.ServiceConfig{
			Image: "redis:8.4.0",
			Ports: []types.ServicePortConfig{{Published: "", Target: 6379}},
			Environment: types.NewMappingWithEquals([]string{
				"ALLOW_EMPTY_PASSWORD=yes",
			}),
		}
	}
}

func WithBackendService(options BackendOptions) StackOption {
	return func(s *Stack) {
		if s.Project.Services == nil {
			s.Project.Services = types.Services{}
		}
		dockerfile := options.Dockerfile
		if dockerfile == "" {
			dockerfile = "Dockerfile.dev.fips"
		}
		s.Project.Services["backend"] = types.ServiceConfig{
			Build: &types.BuildConfig{
				Context:    options.BackendDir,
				Dockerfile: dockerfile,
			},
			Ports: []types.ServicePortConfig{
				{Published: "", Target: 4000},
				{Published: "9229", Target: 9229},
			},
			Environment: types.NewMappingWithEquals([]string{
				"NODE_ENV=development",
				"ENCRYPTION_KEY=VVHnGZ0w98WLgISK4XSJcagezuG6EWRFTk48KE4Y5Mw=",
				"AUTH_SECRET=5lrMXKKWCVocS/uerPsl7V+TX/aaUaI7iDkgl3tSmLE=",
				"DB_CONNECTION_URI=postgres://infisical:infisical@db:5432/infisical",
				"REDIS_URL=redis://redis:6379",
				// TODO: maybe we should generate a random port before passing in so that we can know the port number in
				// 		 the site url ahead?
				"SITE_URL=http://localhost:8080",
				"OTEL_TELEMETRY_COLLECTION_ENABLED=false",
				"ENABLE_MSSQL_SECRET_ROTATION_ENCRYPT=true",
			}),
			Volumes: []types.ServiceVolumeConfig{
				{Source: filepath.Join(options.BackendDir, "src"), Target: "/app/src", Type: types.VolumeTypeBind},
			},
			DependsOn: types.DependsOnConfig{
				"db":    types.ServiceDependency{Condition: "service_started"},
				"redis": types.ServiceDependency{Condition: "service_started"},
			},
			ExtraHosts: map[string][]string{
				"host.docker.internal": {
					"host-gateway",
				},
			},
		}
	}
}

func WithBackendServiceFromEnv() StackOption {
	return WithBackendService(BackendOptionsFromEnv())
}

func WithDefaultStack(backendOptions BackendOptions) StackOption {
	return func(s *Stack) {
		for _, o := range []StackOption{WithDbService(), WithRedisService(), WithBackendService(backendOptions)} {
			o(s)
		}
	}
}

func WithDefaultStackFromEnv() StackOption {
	return WithDefaultStack(BackendOptionsFromEnv())
}

type RunningCompose struct {
	name     string
	client   *testcontainers.DockerClient
	provider *testcontainers.DockerProvider

	containers     map[string]*testcontainers.DockerContainer
	containersLock sync.Mutex
}

func (c *RunningCompose) Up(ctx context.Context, opts ...compose.StackUpOption) error {
	//TODO implement me
	panic("implement me")
}

func (c *RunningCompose) Down(ctx context.Context, opts ...compose.StackDownOption) error {
	//TODO implement me
	panic("implement me")
}

func (c *RunningCompose) Services() []string {
	//TODO implement me
	panic("implement me")
}

func (c *RunningCompose) WaitForService(s string, strategy wait.Strategy) compose.ComposeStack {
	//TODO implement me
	panic("implement me")
}

func (c *RunningCompose) WithEnv(m map[string]string) compose.ComposeStack {
	panic("Cannot modify running compose")
}

func (c *RunningCompose) WithOsEnv() compose.ComposeStack {
	panic("Cannot modify running compose")
}

func (c *RunningCompose) cachedContainer(svcName string) *testcontainers.DockerContainer {
	c.containersLock.Lock()
	defer c.containersLock.Unlock()

	return c.containers[svcName]
}

func (c *RunningCompose) ServiceContainer(ctx context.Context, svcName string) (*testcontainers.DockerContainer, error) {
	if ctr := c.cachedContainer(svcName); c != nil {
		return ctr, nil
	}

	containers, err := c.client.ContainerList(ctx, container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", fmt.Sprintf("%s=%s", api.ProjectLabel, c.name)),
			filters.Arg("label", fmt.Sprintf("%s=%s", api.ServiceLabel, svcName)),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("container list: %w", err)
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("no container found for service name %s", svcName)
	}

	ctr, err := c.provider.ContainerFromType(ctx, containers[0])
	if err != nil {
		return nil, fmt.Errorf("container from type: %w", err)
	}

	c.containersLock.Lock()
	defer c.containersLock.Unlock()
	c.containers[svcName] = ctr
}
