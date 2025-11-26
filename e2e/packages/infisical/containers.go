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

const tmpl = `
services:
  db:
    image: postgres:14-alpine
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: infisical
      POSTGRES_USER: infisical
      POSTGRES_DB: infisical

  redis:
    image: redis
    environment:
      - ALLOW_EMPTY_PASSWORD=yes
    ports:
      - 6379:6379
`

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
		WaitForService("db", wait.ForListeningPort("5432/tcp")).
		Up(context.TODO())
	if err != nil {
		panic(err)
	}
}
