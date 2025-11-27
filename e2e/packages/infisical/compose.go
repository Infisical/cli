package infisical

import (
	"bytes"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
	"os"
	"path/filepath"
	"time"
)

type Stack struct {
	Project *types.Project
}

type StackOption func(*Stack)

type BackendOptions struct {
	BackendDir string
	Dockerfile string
}

func (s *Stack) ToCompose() (Compose, error) {
	data, err := s.Project.MarshalYAML()
	if err != nil {
		return nil, err
	}
	dockerCompose, err := compose.NewDockerComposeWith(
		compose.WithStackReaders(bytes.NewReader(data)),
	)
	if err != nil {
		return nil, err
	}
	return NewComposeWrapper(dockerCompose), nil
}

func (s *Stack) ToComposeWithWaitingForService() (Compose, error) {
	dockerCompose, err := s.ToCompose()
	if err != nil {
		return nil, err
	}
	waited := dockerCompose.WaitForService(
		"backend",
		wait.ForListeningPort("4000/tcp").
			WithStartupTimeout(120*time.Second),
	)
	return NewComposeWrapper(waited), nil
}

func BackendOptionsFromEnv() BackendOptions {
	backendDir, found := os.LookupEnv("INFISICAL_BACKEND_DIR")
	if !found {
		panic("INFISICAL_BACKEND_DIR not set")
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
