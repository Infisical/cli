package mongodb

import (
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
)

// srvCache caches SRV resolution results to avoid repeated DNS lookups.
// MongoDB SRV hostnames rarely change; caching for 5 minutes eliminates
// the 100ms-8s DNS overhead on every connection.
var srvCache = &srvCacheStore{
	entries: make(map[string]*srvCacheEntry),
}

const srvCacheTTL = 5 * time.Minute

type srvCacheEntry struct {
	host      string
	port      int
	opts      map[string]string
	expiresAt time.Time
}

type srvCacheStore struct {
	mu      sync.RWMutex
	entries map[string]*srvCacheEntry
}

func (c *srvCacheStore) get(hostname string) (host string, port int, opts map[string]string, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[hostname]
	if !exists || time.Now().After(entry.expiresAt) {
		return "", 0, nil, false
	}
	return entry.host, entry.port, entry.opts, true
}

func (c *srvCacheStore) set(hostname, host string, port int, opts map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[hostname] = &srvCacheEntry{
		host:      host,
		port:      port,
		opts:      opts,
		expiresAt: time.Now().Add(srvCacheTTL),
	}
}

// connPool is a package-level pool of authenticated upstream MongoDB connections,
// keyed by session ID. When the MongoDB driver closes a client TCP connection
// and opens a new one (which happens every ~10-20s for monitoring), the new
// proxy instance can reuse an already-authenticated server connection instead
// of paying the full SRV + TCP/TLS + SCRAM cost again.
var connPool = &mongoConnPool{
	sessions: make(map[string]*sessionConns),
}

const (
	poolMaxIdle    = 5
	poolMaxAge     = 5 * time.Minute
	poolPingTimout = 500 * time.Millisecond
)

type pooledConn struct {
	conn      net.Conn
	createdAt time.Time
}

type sessionConns struct {
	mu   sync.Mutex
	idle []*pooledConn
}

type mongoConnPool struct {
	mu       sync.RWMutex
	sessions map[string]*sessionConns
}

// Get retrieves an idle connection for the given session, or returns nil.
// The returned connection is validated with a MongoDB ping before returning.
func (p *mongoConnPool) Get(sessionID string) net.Conn {
	p.mu.RLock()
	sc, ok := p.sessions[sessionID]
	p.mu.RUnlock()
	if !ok {
		return nil
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	now := time.Now()
	for len(sc.idle) > 0 {
		// Pop from the end (LIFO — most recently used connection)
		pc := sc.idle[len(sc.idle)-1]
		sc.idle = sc.idle[:len(sc.idle)-1]

		if now.Sub(pc.createdAt) > poolMaxAge {
			log.Debug().Str("sessionID", sessionID).Msg("[DIAG-CONNPOOL] discarding expired pooled connection") // [DIAG-CONNPOOL]
			pc.conn.Close()
			continue
		}

		// Validate the connection is still alive with a ping
		if err := mongoPing(pc.conn); err != nil {
			log.Debug().Err(err).Str("sessionID", sessionID).Msg("[DIAG-CONNPOOL] pooled connection failed ping, discarding") // [DIAG-CONNPOOL]
			pc.conn.Close()
			continue
		}

		log.Info().Str("sessionID", sessionID).Dur("age_ms", now.Sub(pc.createdAt)).Msg("[DIAG-CONNPOOL] reusing pooled connection") // [DIAG-CONNPOOL]
		return pc.conn
	}

	return nil
}

// Put returns a connection to the pool for reuse.
func (p *mongoConnPool) Put(sessionID string, conn net.Conn) {
	p.mu.Lock()
	sc, ok := p.sessions[sessionID]
	if !ok {
		sc = &sessionConns{}
		p.sessions[sessionID] = sc
	}
	p.mu.Unlock()

	sc.mu.Lock()
	defer sc.mu.Unlock()

	if len(sc.idle) >= poolMaxIdle {
		log.Debug().Str("sessionID", sessionID).Msg("[DIAG-CONNPOOL] pool full, closing connection") // [DIAG-CONNPOOL]
		conn.Close()
		return
	}

	sc.idle = append(sc.idle, &pooledConn{
		conn:      conn,
		createdAt: time.Now(),
	})
	log.Info().Str("sessionID", sessionID).Int("poolSize", len(sc.idle)).Msg("[DIAG-CONNPOOL] connection returned to pool") // [DIAG-CONNPOOL]
}

// CloseAll closes all pooled connections for a session (called on session termination).
func (p *mongoConnPool) CloseAll(sessionID string) {
	p.mu.Lock()
	sc, ok := p.sessions[sessionID]
	if ok {
		delete(p.sessions, sessionID)
	}
	p.mu.Unlock()

	if !ok {
		return
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	for _, pc := range sc.idle {
		pc.conn.Close()
	}
	log.Debug().Str("sessionID", sessionID).Int("closed", len(sc.idle)).Msg("Closed all pooled connections for session")
}

// CloseSessionPool closes all pooled connections for a session.
// Called from HandlePAMCancellation when a session is terminated.
func CloseSessionPool(sessionID string) {
	connPool.CloseAll(sessionID)
}

// mongoPing sends a MongoDB ping command and verifies the response.
// Used to validate that a pooled connection is still usable.
func mongoPing(conn net.Conn) error {
	conn.SetDeadline(time.Now().Add(poolPingTimout))
	defer conn.SetDeadline(time.Time{}) // clear deadline

	pingCmd, err := bson.Marshal(bson.D{
		{Key: "ping", Value: 1},
		{Key: "$db", Value: "admin"},
	})
	if err != nil {
		return err
	}

	resp, err := sendCommand(conn, pingCmd)
	if err != nil {
		return err
	}

	return checkCommandOk(resp)
}
