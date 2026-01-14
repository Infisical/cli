package client

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// RedisConfig holds Redis connection configuration
type RedisConfig struct {
	Host     string
	Port     int
	Password string
}

// DefaultRedisConfig returns the default Redis configuration
func DefaultRedisConfig() RedisConfig {
	return RedisConfig{
		Host:     "localhost",
		Port:     6379,
		Password: "",
	}
}

// ResetRedisOptions holds options for resetting Redis
type ResetRedisOptions struct {
	RedisConfig RedisConfig
}

// DefaultResetRedisOptions returns default options for resetting Redis
func DefaultResetRedisOptions() ResetRedisOptions {
	return ResetRedisOptions{
		RedisConfig: DefaultRedisConfig(),
	}
}

// ResetRedis resets the Redis database by flushing all keys.
// It accepts a port provider to get service ports, and options to configure the reset behavior.
func ResetRedis(ctx context.Context, opts ...func(*ResetRedisOptions)) error {
	options := DefaultResetRedisOptions()
	for _, opt := range opts {
		opt(&options)
	}

	return resetRedisDB(ctx, options)
}

// resetRedisDB resets the Redis database by flushing all keys.
func resetRedisDB(ctx context.Context, opts ResetRedisOptions) error {
	slog.Info("Resetting Postgres database")
	addr := fmt.Sprintf("%s:%d", opts.RedisConfig.Host, opts.RedisConfig.Port)
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: opts.RedisConfig.Password,
	})
	defer func() {
		_ = rdb.Close()
	}()

	// Test the connection
	pong, err := rdb.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	slog.Info("Connected to Redis", "pong", pong)

	// Clear all keys in the current database
	err = rdb.FlushAll(ctx).Err()
	if err != nil {
		return fmt.Errorf("failed to flush Redis database: %w", err)
	}
	slog.Info("All keys cleared successfully from Redis database")

	return nil
}

// WithRedisConfig sets the Redis configuration
func WithRedisConfig(config RedisConfig) func(*ResetRedisOptions) {
	return func(opts *ResetRedisOptions) {
		opts.RedisConfig = config
	}
}
