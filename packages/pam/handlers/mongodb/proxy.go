package mongodb

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type MongoDBProxyConfig struct {
	Host           string
	Port           int // 0 means SRV (mongodb+srv://)
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	SessionLogger  session.SessionLogger
}

type MongoDBProxy struct {
	config MongoDBProxyConfig
}

func NewMongoDBProxy(config MongoDBProxyConfig) *MongoDBProxy {
	return &MongoDBProxy{config: config}
}

func (p *MongoDBProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	defer func() {
		if err := p.config.SessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().
		Str("sessionID", p.config.SessionID).
		Msg("New MongoDB connection for PAM session")

	client, err := p.connectToTarget(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to target MongoDB: %w", err)
	}
	defer client.Disconnect(ctx)

	b := newBridge(client, clientConn, p.config.SessionLogger, p.config.InjectDatabase)
	return b.run(ctx)
}

func (p *MongoDBProxy) connectToTarget(ctx context.Context) (*mongo.Client, error) {
	isSRV := p.config.Port == 0
	targetAddr := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)

	// Verify raw TCP connectivity first (same pattern as other PAM handlers).
	// This surfaces network errors immediately instead of waiting for the
	// driver's 10-second server selection timeout.
	if !isSRV {
		log.Debug().Str("target", targetAddr).Msg("Testing TCP connectivity to MongoDB target")
		testConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("cannot reach MongoDB at %s: %w", targetAddr, err)
		}
		testConn.Close()
		log.Debug().Str("target", targetAddr).Msg("TCP connectivity to MongoDB target verified")
	}

	var opts *options.ClientOptions
	if isSRV {
		opts = options.Client().ApplyURI(fmt.Sprintf("mongodb+srv://%s/", p.config.Host))
	} else {
		opts = options.Client().
			SetHosts([]string{targetAddr}).
			SetDirect(true)
	}

	opts.SetMaxPoolSize(1)
	opts.SetReadPreference(readpref.Primary())
	opts.SetConnectTimeout(5 * time.Second)
	opts.SetServerSelectionTimeout(10 * time.Second)
	opts.SetHeartbeatInterval(2 * time.Second)

	// Log handshake failures so auth/TLS errors are visible instead of
	// being buried inside a generic "server selection timeout".
	opts.SetServerMonitor(&event.ServerMonitor{
		ServerHeartbeatFailed: func(e *event.ServerHeartbeatFailedEvent) {
			log.Error().
				Err(e.Failure).
				Str("address", e.ConnectionID).
				Msg("MongoDB server heartbeat failed")
		},
	})

	if p.config.InjectUsername != "" && p.config.InjectPassword != "" {
		opts.SetAuth(options.Credential{
			Username:   p.config.InjectUsername,
			Password:   p.config.InjectPassword,
			AuthSource: "admin",
		})
	}

	if p.config.EnableTLS || isSRV {
		tlsCfg := &tls.Config{}
		if p.config.TLSConfig != nil {
			tlsCfg = p.config.TLSConfig.Clone()
		}
		opts.SetTLSConfig(tlsCfg)
	}

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create MongoDB client: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("failed to verify MongoDB connection: %w", err)
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Str("host", p.config.Host).
		Int("port", p.config.Port).
		Bool("srv", isSRV).
		Msg("Connected to target MongoDB")

	return client, nil
}
