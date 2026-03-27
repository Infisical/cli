package mongodb

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
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

	// Respond to the client's initial hello/ismaster BEFORE connecting to the
	// target. mongosh sends ismaster immediately and times out in 2 seconds
	// (serverSelectionTimeoutMS). connectToTarget can take 1-5s for remote
	// servers, so the bridge wouldn't start in time.
	if err := handleInitialHandshake(clientConn); err != nil {
		return fmt.Errorf("failed to handle initial handshake: %w", err)
	}

	client, err := p.connectToTarget(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to target MongoDB: %w", err)
	}
	defer func() {
		disconnectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Disconnect(disconnectCtx)
	}()

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
		testConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
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
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetServerSelectionTimeout(15 * time.Second)
	opts.SetHeartbeatInterval(30 * time.Second)

	// Log handshake failures so auth/TLS errors are visible instead of
	// being buried inside a generic "server selection timeout".
	// Suppress "context canceled" errors which are expected during shutdown.
	opts.SetServerMonitor(&event.ServerMonitor{
		ServerHeartbeatFailed: func(e *event.ServerHeartbeatFailedEvent) {
			if e.Failure != nil && !strings.Contains(e.Failure.Error(), "context canceled") {
				log.Error().
					Err(e.Failure).
					Str("address", e.ConnectionID).
					Msg("MongoDB server heartbeat failed")
			}
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

// handleInitialHandshake reads the client's first message (OP_QUERY ismaster
// or OP_MSG hello) and responds with a synthetic hello immediately. This
// satisfies mongosh's 2-second serverSelectionTimeoutMS while we connect to
// the real target in the background.
func handleInitialHandshake(conn net.Conn) error {
	hdr, raw, err := readWireMessage(conn)
	if err != nil {
		return fmt.Errorf("failed to read initial client message: %w", err)
	}

	log.Debug().
		Int32("opcode", hdr.OpCode).
		Int32("requestID", hdr.RequestID).
		Msg("Initial handshake message from client")

	syntheticHello, err := bson.Marshal(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "isWritablePrimary", Value: true},
		{Key: "maxBsonObjectSize", Value: int32(16777216)},
		{Key: "maxMessageSizeBytes", Value: int32(48000000)},
		{Key: "maxWriteBatchSize", Value: int32(100000)},
		{Key: "maxWireVersion", Value: int32(21)},
		{Key: "minWireVersion", Value: int32(0)},
		{Key: "readOnly", Value: false},
		{Key: "ok", Value: 1.0},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal synthetic hello: %w", err)
	}

	var reply []byte
	switch hdr.OpCode {
	case opQueryOpCode:
		reply = buildOpReply(hdr.RequestID, syntheticHello)
	case opMsgOpCode:
		reply = buildOpMsgReply(hdr.RequestID, syntheticHello)
	default:
		// Unexpected first message — let the bridge handle it.
		// Put the bytes back... actually we can't, so just respond generically.
		reply = buildOpMsgReply(hdr.RequestID, syntheticHello)
	}

	if err := writeWireMessage(conn, reply); err != nil {
		return fmt.Errorf("failed to write initial handshake response: %w", err)
	}

	_ = raw // consumed the first message
	log.Debug().Msg("Sent synthetic hello response for initial handshake")
	return nil
}
