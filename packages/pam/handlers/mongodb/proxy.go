package mongodb

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
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

	var opts *options.ClientOptions
	if isSRV {
		opts = options.Client().ApplyURI(fmt.Sprintf("mongodb+srv://%s/", p.config.Host))
	} else {
		opts = options.Client().
			SetHosts([]string{fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)}).
			SetDirect(true)
	}

	opts.SetMaxPoolSize(1)
	opts.SetReadPreference(readpref.Primary())
	opts.SetConnectTimeout(30 * time.Second)
	opts.SetServerSelectionTimeout(30 * time.Second)

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
