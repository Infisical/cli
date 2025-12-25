package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/fangpenlin/resp3"
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
	relayHandler *RelayHandler
}

// NewRedisProxy creates a new Redis proxy instance
func NewRedisProxy(config RedisProxyConfig) *RedisProxy {
	return &RedisProxy{config: config}
}

// HandleConnection handles a single client connection
func (p *RedisProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer func(clientConn net.Conn) { _ = clientConn.Close() }(clientConn)

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

	var selfToServerConn net.Conn
	if !p.config.EnableTLS {
		c, err := net.Dial("tcp", p.config.TargetAddr)
		if err != nil {
			return err
		}
		selfToServerConn = c
	} else {
		c, err := tls.Dial("tcp", p.config.TargetAddr, p.config.TLSConfig)
		if err != nil {
			return err
		}
		selfToServerConn = c
	}

	selfToClientRedisConn := NewRedisConn(selfToServerConn)
	defer func(selfToClientRedisConn *RedisConn) { _ = selfToClientRedisConn.Close() }(selfToClientRedisConn)

	if err := selfToClientRedisConn.Writer().WriteCommand("AUTH", p.config.InjectUsername, p.config.InjectPassword); err != nil {
		return err
	}
	if err := selfToClientRedisConn.Writer().Flush(); err != nil {
		return err
	}

	respValue, _, err := selfToClientRedisConn.Reader().ReadValue()
	if err != nil {
		return err
	}
	if respValue.Type != resp3.TypeSimpleString && respValue.Str != "OK" {
		errorMsg := "unknown"
		if respValue.Type == resp3.TypeSimpleError || respValue.Type == resp3.TypeBlobError {
			errorMsg = respValue.Err
		}
		log.Error().Str("errorMsg", errorMsg).Msg("Failed to authenticate with the target redis server")
		return fmt.Errorf("failed to authenticate with the target redis server")
	}

	clientToSelfConn := NewRedisConn(clientConn)
	defer func() { _ = clientToSelfConn.Close() }()

	p.relayHandler = NewRelayHandler(clientToSelfConn, selfToClientRedisConn, p.config.SessionLogger)
	return p.relayHandler.Handle(ctx)
}
