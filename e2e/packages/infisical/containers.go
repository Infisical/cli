package infisical

import (
	"bytes"
	"context"
	"fmt"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/testcontainers/testcontainers-go/modules/compose"
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
	// Create a Project (root struct for Docker Compose)
	project := &types.Project{
		Services: types.Services{
			"web": types.ServiceConfig{
				Image:         "nginx:alpine",
				ContainerName: "myapp_web_1",
				Ports:         []types.ServicePortConfig{{Published: "8080", Target: 80}},
				Environment:   types.NewMappingWithEquals([]string{"ENV=production"}),
				Restart:       "unless-stopped",
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
	dc, err := compose.NewDockerComposeWith(
		compose.WithStackReaders(bytes.NewReader(data)),
	)
	dc.WithEnv(map[string]string{"POSTGRES_PASSWORD": "infisical"})
	dc.Up(context.TODO())
}
