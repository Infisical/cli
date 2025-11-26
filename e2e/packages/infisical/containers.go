package infisical

import (
	"bytes"
	"context"
	"fmt"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
	"gopkg.in/yaml.v3"
)

type Containers struct {
}

func NewContainers() *Containers {
	return &Containers{}
}

func (c *Containers) Up() {
	project := &types.Project{
		Services: types.Services{
			"db": types.ServiceConfig{
				Image: "redis",
				Ports: []types.ServicePortConfig{{Published: "5432", Target: 5432}},
				Environment: types.NewMappingWithEquals([]string{
					"POSTGRES_DB=infisical",
					"POSTGRES_USER=infisical",
					"POSTGRES_PASSWORD=infisical",
				}),
			},
			"redis": types.ServiceConfig{
				Image: "redis:8.4.0",
				Ports: []types.ServicePortConfig{{Published: "6379", Target: 6379}},
				Environment: types.NewMappingWithEquals([]string{
					"ALLOW_EMPTY_PASSWORD=yes",
				}),
			},
			"backend": types.ServiceConfig{
				Build: &types.BuildConfig{
					Context:    "/Users/fangpenlin/workspace/infisical/backend",
					Dockerfile: "Dockerfile.dev.fips",
				},
				Ports: []types.ServicePortConfig{
					{Published: "4000", Target: 4000},
					{Published: "9229", Target: 9229},
				},
				DependsOn: types.DependsOnConfig{
					"db":    types.ServiceDependency{Condition: "service_started"},
					"redis": types.ServiceDependency{Condition: "service_started"},
				},
			},
		},
	}

	data, err := yaml.Marshal(&project)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	//t := template.Must(template.New("docker-compose.yaml").Parse(tmpl))
	//var buf bytes.Buffer
	//err = t.Execute(&buf, map[string]interface{}{})
	//if err != nil {
	//	panic(err)
	//}
	stack, err := compose.NewDockerComposeWith(
		compose.WithStackReaders(bytes.NewReader(data)),
	)
	if err != nil {
		panic(err)
	}
	err = stack.WithEnv(map[string]string{"POSTGRES_PASSWORD": "infisical"}).
		WaitForService("backend", wait.ForListeningPort("4000/tcp")).
		Up(context.TODO())
	if err != nil {
		panic(err)
	}
}
