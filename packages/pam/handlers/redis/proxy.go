package redis

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// RedisProxyConfig holds configuration for the Redis proxy
type RedisProxyConfig struct {
	TargetAddr     string
	InjectUsername string
	InjectPassword string
	InjectDatabase int
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	SessionLogger  session.SessionLogger
}

// RedisProxy handles proxying Redis connections
type RedisProxy struct {
	config       RedisProxyConfig
	client       *redis.Client
	relayHandler *RelayHandler
}

// NewRedisProxy creates a new Redis proxy instance
func NewRedisProxy(config RedisProxyConfig) *RedisProxy {
	return &RedisProxy{config: config}
}

// HandleConnection handles a single client connection
func (p *RedisProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	sessionID := p.config.SessionID

	// Ensure session logger cleanup
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", sessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().
		Str("sessionID", sessionID).
		Msg("New Redis connection for PAM session")

	// TODO: support TLS
	rdb := redis.NewClient(&redis.Options{
		Addr:     p.config.TargetAddr,
		Username: p.config.InjectUsername,
		Password: p.config.InjectPassword,
		DB:       p.config.InjectDatabase,
	})
	p.client = rdb

	// TODO: open a new conn to the actual redis server
	p.relayHandler = NewRelayHandler(clientConn, p.config.SessionLogger)
	// TODO: run this is a go routine
	err := p.relayHandler.Handle()
	if err != nil {
		return err
	}

	return nil
}
