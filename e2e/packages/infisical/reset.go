package infisical

import (
	"context"
	"fmt"
	"strconv"

	"github.com/docker/go-connections/nat"
	"github.com/infisical/cli/e2e-tests/packages/client"
	"github.com/testcontainers/testcontainers-go/modules/compose"
)

// composePortProvider implements client.ServicePortProvider for compose stacks
type composePortProvider struct {
	stack compose.ComposeStack
}

// GetServicePort gets the mapped port for a service
func (p *composePortProvider) GetServicePort(ctx context.Context, serviceName string, internalPort string) (string, error) {
	c, err := p.stack.ServiceContainer(ctx, serviceName)
	if err != nil {
		return "", fmt.Errorf("failed to get %s c: %w", serviceName, err)
	}
	port, err := c.MappedPort(ctx, nat.Port(internalPort))
	if err != nil {
		return "", fmt.Errorf("failed to get %s port %s: %w", serviceName, internalPort, err)
	}
	return port.Port(), nil
}

// Reset resets the whole instance of Infisical backend service to its original state after first time booting up
func Reset(ctx context.Context, stack compose.ComposeStack) error {
	// Create port provider to get service ports
	portProvider := &composePortProvider{stack: stack}

	// Get PostgreSQL port
	dbPort, err := portProvider.GetServicePort(ctx, "db", "5432")
	if err != nil {
		return fmt.Errorf("failed to get db port: %w", err)
	}

	// Get Redis port
	redisPort, err := portProvider.GetServicePort(ctx, "redis", "6379")
	if err != nil {
		return fmt.Errorf("failed to get redis port: %w", err)
	}

	// Reset PostgreSQL database
	if err := client.ResetDB(ctx, client.WithDatabaseConfig(client.DatabaseConfig{
		User:     "infisical",
		Password: "infisical",
		Database: "infisical",
		Host:     "localhost",
		Port:     dbPort,
	})); err != nil {
		return err
	}

	// Reset Redis database
	redisPortInt, err := strconv.Atoi(redisPort)
	if err != nil {
		return fmt.Errorf("failed to parse redis port: %w", err)
	}
	if err := client.ResetRedis(ctx, client.WithRedisConfig(client.RedisConfig{
		Host:     "localhost",
		Port:     redisPortInt,
		Password: "",
	})); err != nil {
		return err
	}

	return nil
}
