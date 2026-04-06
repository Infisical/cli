package mongodb

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/description"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/topology"
)

type MongoDBProxyConfig struct {
	Host           string // "host:port", "h1:p1,h2:p2", SRV hostname, or full URI (mongodb[+srv]://...)
	InjectUsername string // Real DB username (injected, never shown to client)
	InjectPassword string // Real DB password (injected, never shown to client)
	InjectDatabase string // Target database (used when Host is not a URI)
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
}

type MongoDBProxy struct {
	config   MongoDBProxyConfig
	top      *topology.Topology
	selector description.ServerSelector
}

// primarySelector selects writable (primary) servers for proxying.
type primarySelector struct{}

func (primarySelector) SelectServer(td description.Topology, candidates []description.Server) ([]description.Server, error) {
	var result []description.Server
	for _, s := range candidates {
		if s.Kind == description.ServerKindRSPrimary || s.Kind == description.ServerKindStandalone || s.Kind == description.ServerKindMongos {
			result = append(result, s)
		}
	}
	return result, nil
}

// buildURI constructs a MongoDB connection URI from the proxy config.
// If Host is a full URI, credentials are injected preserving any existing options.
// If Host is a plain host spec, a URI is built from it + InjectDatabase.
func buildURI(c MongoDBProxyConfig) string {
	host := c.Host

	// If host is already a MongoDB URI, inject credentials into it
	if strings.HasPrefix(host, "mongodb://") || strings.HasPrefix(host, "mongodb+srv://") {
		return injectCredentials(host, c.InjectUsername, c.InjectPassword)
	}

	// Plain host spec — build URI from parts
	// Bare hostname (no : and no ,) = SRV, otherwise standard
	isSRV := !strings.Contains(host, ":") && !strings.Contains(host, ",")

	scheme := "mongodb"
	if isSRV {
		scheme = "mongodb+srv"
	}

	return fmt.Sprintf("%s://%s:%s@%s/%s",
		scheme,
		url.PathEscape(c.InjectUsername),
		url.PathEscape(c.InjectPassword),
		host,
		url.PathEscape(c.InjectDatabase),
	)
}

// isSRVURI returns true if the host is or will become an SRV-based connection.
func isSRVURI(host string) bool {
	if strings.HasPrefix(host, "mongodb+srv://") {
		return true
	}
	// Plain hostname without port or comma = SRV (see buildURI)
	if !strings.HasPrefix(host, "mongodb://") && !strings.Contains(host, ":") && !strings.Contains(host, ",") {
		return true
	}
	return false
}

// injectCredentials inserts username:password into a MongoDB URI that has no credentials.
// e.g. "mongodb+srv://cluster.abc.net/mydb?authSource=admin" becomes
// "mongodb+srv://user:pass@cluster.abc.net/mydb?authSource=admin"
func injectCredentials(rawURI, username, password string) string {
	u, err := url.Parse(rawURI)
	if err != nil {
		// Fallback: insert credentials after scheme://
		schemeEnd := strings.Index(rawURI, "://")
		if schemeEnd == -1 {
			return rawURI
		}
		return rawURI[:schemeEnd+3] +
			url.PathEscape(username) + ":" + url.PathEscape(password) + "@" +
			rawURI[schemeEnd+3:]
	}

	u.User = url.UserPassword(username, password)
	return u.String()
}

// NewMongoDBProxy creates a proxy with a driver-managed topology.
// The driver handles: SRV resolution, TLS, SCRAM auth, connection pooling,
// topology discovery, and server selection.
func NewMongoDBProxy(ctx context.Context, config MongoDBProxyConfig) (*MongoDBProxy, error) {
	uri := buildURI(config)

	// Let the driver parse the URI (handles SRV resolution, TXT records, etc.)
	clientOpts := options.Client().ApplyURI(uri)
	if config.EnableTLS && config.TLSConfig != nil {
		clientOpts.SetTLSConfig(config.TLSConfig)
	}

	// For non-SRV single-host connections, use direct mode to skip topology
	// discovery and connect immediately.
	if clientOpts.Direct == nil && !isSRVURI(config.Host) {
		clientOpts.SetDirect(true)
	}

	// Disable compression — proxy forwards raw wire bytes that must be
	// readable without decompression.
	clientOpts.SetCompressors([]string{})

	// Create topology to leverage driver's connection management and auth.
	topoConfig, err := topology.NewConfig(clientOpts, nil)
	if err != nil {
		return nil, fmt.Errorf("topology config: %w", err)
	}

	top, err := topology.New(topoConfig)
	if err != nil {
		return nil, fmt.Errorf("create topology: %w", err)
	}
	if err := top.Connect(); err != nil {
		return nil, fmt.Errorf("connect topology: %w", err)
	}

	// Verify full connectivity: server selection, TCP, TLS, and SCRAM auth.
	// Fail fast during init rather than on the first client connection.
	selectCtx, selectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer selectCancel()
	selector := primarySelector{}
	server, err := top.SelectServer(selectCtx, selector)
	if err != nil {
		top.Disconnect(ctx) //nolint:errcheck
		return nil, fmt.Errorf("server selection failed (MongoDB unreachable?): %w", err)
	}
	conn, err := server.Connection(selectCtx)
	if err != nil {
		top.Disconnect(ctx) //nolint:errcheck
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}
	conn.Close()

	log.Info().
		Str("sessionID", config.SessionID).
		Str("host", config.Host).
		Msg("MongoDB topology connected for PAM session")

	return &MongoDBProxy{
		config:   config,
		top:      top,
		selector: selector,
	}, nil
}

// HandleConnection handles a single client connection by bridging it to a
// pooled, authenticated server connection from the driver's topology.
// Each connection gets its own session logger for recording.
func (p *MongoDBProxy) HandleConnection(ctx context.Context, clientConn net.Conn, sessionLogger session.SessionLogger) error {
	defer clientConn.Close()
	defer func() {
		if err := sessionLogger.Close(); err != nil {
			log.Error().Err(err).Str("sessionID", p.config.SessionID).Msg("Failed to close session logger")
		}
	}()

	log.Info().
		Str("sessionID", p.config.SessionID).
		Msg("New MongoDB client connection for PAM session")

	// Get a pooled, authenticated connection from the driver
	server, err := p.top.SelectServer(ctx, p.selector)
	if err != nil {
		return fmt.Errorf("server selection: %w", err)
	}

	conn, err := server.Connection(ctx)
	if err != nil {
		return fmt.Errorf("server connection: %w", err)
	}
	defer func() {
		// Expire rather than return to pool — raw wire forwarding means
		// the driver cannot guarantee connection state.
		type expirable interface{ Expire() error }
		if expirer, ok := conn.ReadWriteCloser.(expirable); ok {
			expirer.Expire() //nolint:errcheck
		}
		conn.Close()
	}()

	b := newBridge(conn, clientConn, sessionLogger, p.config.InjectDatabase)
	return b.run(ctx)
}

// Close disconnects the topology and releases all pooled connections.
func (p *MongoDBProxy) Close(ctx context.Context) error {
	log.Info().
		Str("sessionID", p.config.SessionID).
		Msg("Closing MongoDB topology for PAM session")
	return p.top.Disconnect(ctx)
}
