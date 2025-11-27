package infisical

import (
	"github.com/compose-spec/compose-go/v2/types"
	"os"
	"path/filepath"
)

type Stack struct {
	Project *types.Project
}

type BackendOptions struct {
	BackendDir string
	Dockerfile string
}

type Option func(*Stack)

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

func NewStack(options ...Option) *Stack {
	s := &Stack{
		Project: &types.Project{},
	}
	for _, o := range options {
		o(s)
	}
	return s
}

func WithDbService() Option {
	return func(s *Stack) {
		if s.Project.Services == nil {
			s.Project.Services = types.Services{}
		}
		s.Project.Services["db"] = types.ServiceConfig{
			Image: "postgres:14-alpine",
			Ports: []types.ServicePortConfig{{Published: "5432", Target: 5432}},
			Environment: types.NewMappingWithEquals([]string{
				"POSTGRES_DB=infisical",
				"POSTGRES_USER=infisical",
				"POSTGRES_PASSWORD=infisical",
			}),
		}
	}
}

func WithRedisService() Option {
	return func(s *Stack) {
		if s.Project.Services == nil {
			s.Project.Services = types.Services{}
		}
		s.Project.Services["redis"] = types.ServiceConfig{
			Image: "redis:8.4.0",
			Ports: []types.ServicePortConfig{{Published: "6379", Target: 6379}},
			Environment: types.NewMappingWithEquals([]string{
				"ALLOW_EMPTY_PASSWORD=yes",
			}),
		}
	}
}

func WithBackendService(options BackendOptions) Option {
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
				{Published: "4000", Target: 4000},
				{Published: "9229", Target: 9229},
			},
			Environment: types.NewMappingWithEquals([]string{
				"ENCRYPTION_KEY=VVHnGZ0w98WLgISK4XSJcagezuG6EWRFTk48KE4Y5Mw=",
				"AUTH_SECRET=5lrMXKKWCVocS/uerPsl7V+TX/aaUaI7iDkgl3tSmLE=",
				"DB_CONNECTION_URI=postgres://infisical:infisical@db:5432/infisical",
				"REDIS_URL=redis://redis:6379",
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

func WithBackendServiceFromEnv() Option {
	return WithBackendService(BackendOptionsFromEnv())
}

func WithDefaultStack(backendOptions BackendOptions) Option {
	return func(s *Stack) {
		for _, o := range []Option{WithDbService(), WithRedisService(), WithBackendService(backendOptions)} {
			o(s)
		}
	}
}

func WithDefaultStackFromEnv() Option {
	return WithDefaultStack(BackendOptionsFromEnv())
}
