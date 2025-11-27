package infisical

import (
	"context"
	"fmt"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Compose basically the same as compose.ComposeStack but comes with some extra helper functions to make our life
// much easier
type Compose interface {
	compose.ComposeStack

	// ApiUrl Get backend API url
	ApiUrl(ctx context.Context) (string, error)
}

type ComposeWrapper struct {
	ComposeStack compose.ComposeStack
}

func NewComposeWrapper(composeStack compose.ComposeStack) *ComposeWrapper {
	return &ComposeWrapper{ComposeStack: composeStack}
}

func (c ComposeWrapper) Up(ctx context.Context, opts ...compose.StackUpOption) error {
	return c.ComposeStack.Up(ctx, opts...)
}

func (c ComposeWrapper) Down(ctx context.Context, opts ...compose.StackDownOption) error {
	return c.ComposeStack.Down(ctx, opts...)
}

func (c ComposeWrapper) Services() []string {
	return c.ComposeStack.Services()
}

func (c ComposeWrapper) WaitForService(s string, strategy wait.Strategy) compose.ComposeStack {
	return c.ComposeStack.WaitForService(s, strategy)
}

func (c ComposeWrapper) WithEnv(m map[string]string) compose.ComposeStack {
	return c.ComposeStack.WithEnv(m)
}

func (c ComposeWrapper) WithOsEnv() compose.ComposeStack {
	return c.ComposeStack.WithOsEnv()
}

func (c ComposeWrapper) ServiceContainer(ctx context.Context, svcName string) (*testcontainers.DockerContainer, error) {
	return c.ComposeStack.ServiceContainer(ctx, svcName)
}

func (c ComposeWrapper) ApiUrl(ctx context.Context) (string, error) {
	backend, err := c.ComposeStack.ServiceContainer(ctx, "backend")
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
