package mongodb

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
)

type MongoDBProxyConfig struct {
	TargetAddr     string
	InjectUsername string
	InjectPassword string
	InjectDatabase string
	EnableTLS      bool
	TLSConfig      *tls.Config
	SessionID      string
	SessionLogger  session.SessionLogger
}

type pendingQuery struct {
	summary   string
	timestamp time.Time
}

type MongoDBProxy struct {
	config       MongoDBProxyConfig
	mu           sync.Mutex
	pendingQuery *pendingQuery
}

func NewMongoDBProxy(config MongoDBProxyConfig) *MongoDBProxy {
	return &MongoDBProxy{config: config}
}

func (p *MongoDBProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()
	defer p.config.SessionLogger.Close()

	log.Info().Str("sessionID", p.config.SessionID).Msg("MongoDB PAM session started")

	// === PHASE 1: Handle client handshake (proxy acts as MongoDB server) ===
	log.Info().Str("sessionID", p.config.SessionID).Msg("Starting client handshake...")
	if err := p.handleClientHandshake(clientConn); err != nil {
		return fmt.Errorf("client handshake failed: %w", err)
	}
	log.Info().Str("sessionID", p.config.SessionID).Msg("Client handshake completed")

	// === PHASE 2: Connect to server and authenticate (proxy acts as MongoDB client) ===
	serverConn, err := p.connectAndAuthenticateToServer()
	if err != nil {
		return fmt.Errorf("server connection failed: %w", err)
	}
	defer serverConn.Close()

	// === PHASE 3: Proxy traffic ===
	errCh := make(chan error, 2)
	go p.proxyToServer(clientConn, serverConn, errCh)
	go p.proxyToClient(serverConn, clientConn, errCh)

	select {
	case err := <-errCh:
		if err != nil && err != io.EOF {
			log.Debug().Err(err).Str("sessionID", p.config.SessionID).Msg("Connection ended")
		}
	case <-ctx.Done():
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("MongoDB PAM session ended")
	return nil
}

// handleClientHandshake reads the client's hello/ismaster and responds without
// advertising authentication mechanisms.
//
// MongoDB SCRAM is a mutual authentication protocol — the client verifies the server's
// signature, so we can't fake a successful SCRAM exchange without knowing the client's
// password. Instead, we tell the client that no authentication is required by omitting
// saslSupportedMechs from the hello response. The proxy handles all real authentication
// to the server in Phase 2.
//
// If a client still sends saslStart (e.g., because credentials are in the connection string),
// we return an error telling them to connect without credentials.
func (p *MongoDBProxy) handleClientHandshake(clientConn net.Conn) error {
	msg, err := ReadMessage(clientConn)
	if err != nil {
		return fmt.Errorf("read client hello: %w", err)
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Int32("opCode", msg.Header.OpCode).
		Msg("Received client message")

	// Build the hello response that does NOT advertise any auth mechanisms.
	// Without saslSupportedMechs, the client won't attempt authentication.
	// We also don't advertise compression to ensure messages stay readable for audit logging.
	helloResponse := bson.D{
		{Key: "ismaster", Value: true},
		{Key: "maxBsonObjectSize", Value: int32(16 * 1024 * 1024)},
		{Key: "maxMessageSizeBytes", Value: int32(48 * 1024 * 1024)},
		{Key: "maxWriteBatchSize", Value: int32(100000)},
		{Key: "maxWireVersion", Value: int32(17)},
		{Key: "minWireVersion", Value: int32(0)},
		{Key: "ok", Value: 1.0},
	}

	switch msg.Header.OpCode {
	case OpMsg:
		// Modern drivers send OP_MSG with {hello: 1} or {ismaster: 1}
		body, parseErr := ParseOpMsgBody(msg.Payload)
		if parseErr != nil {
			return fmt.Errorf("parse client hello OP_MSG: %w", parseErr)
		}

		cmdName := ExtractCommandName(body)
		if cmdName == "saslStart" {
			return fmt.Errorf("client attempted authentication — connect without credentials " +
				"(the proxy handles authentication to the real MongoDB server)")
		}

		log.Info().
			Str("sessionID", p.config.SessionID).
			Str("command", cmdName).
			Msg("Client sent hello command")

		respBytes, buildErr := BuildOpMsg(nextRequestID(), msg.Header.RequestID, helloResponse)
		if buildErr != nil {
			return fmt.Errorf("build hello response: %w", buildErr)
		}
		if _, writeErr := clientConn.Write(respBytes); writeErr != nil {
			return fmt.Errorf("send hello response: %w", writeErr)
		}

	case OpQuery:
		// Legacy drivers (pre-3.6) send OP_QUERY for ismaster to admin.$cmd
		log.Info().Str("sessionID", p.config.SessionID).Msg("Client sent legacy OP_QUERY hello")

		respBytes, buildErr := BuildOpReply(nextRequestID(), msg.Header.RequestID, helloResponse)
		if buildErr != nil {
			return fmt.Errorf("build legacy hello response: %w", buildErr)
		}
		if _, writeErr := clientConn.Write(respBytes); writeErr != nil {
			return fmt.Errorf("send legacy hello response: %w", writeErr)
		}

	default:
		return fmt.Errorf("unexpected opCode %d during handshake (expected hello/ismaster)", msg.Header.OpCode)
	}

	return nil
}

// connectAndAuthenticateToServer dials the real MongoDB server and authenticates
// using injected credentials via SCRAM-SHA-256.
func (p *MongoDBProxy) connectAndAuthenticateToServer() (net.Conn, error) {
	var serverConn net.Conn
	var err error

	if p.config.EnableTLS {
		if p.config.TLSConfig == nil {
			return nil, fmt.Errorf("TLS requested but no TLS configuration provided")
		}
		serverConn, err = tls.Dial("tcp", p.config.TargetAddr, p.config.TLSConfig)
	} else {
		serverConn, err = net.Dial("tcp", p.config.TargetAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}

	log.Info().
		Str("sessionID", p.config.SessionID).
		Str("target", p.config.TargetAddr).
		Bool("tls", p.config.EnableTLS).
		Msg("Connected to MongoDB server")

	// Send hello to the real server
	helloDoc := bson.D{
		{Key: "hello", Value: int32(1)},
		{Key: "$db", Value: "admin"},
	}
	// Include saslSupportedMechs to let the server tell us what it supports
	if p.config.InjectUsername != "" {
		helloDoc = append(helloDoc, bson.E{
			Key:   "saslSupportedMechs",
			Value: fmt.Sprintf("admin.%s", p.config.InjectUsername),
		})
	}

	helloBytes, err := BuildOpMsg(nextRequestID(), 0, helloDoc)
	if err != nil {
		serverConn.Close()
		return nil, fmt.Errorf("build server hello: %w", err)
	}
	if _, err := serverConn.Write(helloBytes); err != nil {
		serverConn.Close()
		return nil, fmt.Errorf("send server hello: %w", err)
	}

	helloResp, err := ReadMessage(serverConn)
	if err != nil {
		serverConn.Close()
		return nil, fmt.Errorf("read server hello response: %w", err)
	}

	// Validate the server responded successfully
	if helloResp.Header.OpCode == OpMsg {
		body, parseErr := ParseOpMsgBody(helloResp.Payload)
		if parseErr == nil {
			okVal, lookupErr := body.LookupErr("ok")
			if lookupErr == nil {
				var ok float64
				switch okVal.Type {
				case bson.TypeDouble:
					ok = okVal.Double()
				case bson.TypeInt32:
					ok = float64(okVal.Int32())
				}
				if ok != 1 {
					serverConn.Close()
					return nil, fmt.Errorf("server hello failed")
				}
			}
		}
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("Server hello successful, starting SCRAM-SHA-256 auth")

	// Authenticate with injected credentials
	if err := authenticateScramSHA256(serverConn, p.config.InjectUsername, p.config.InjectPassword); err != nil {
		serverConn.Close()
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	log.Info().Str("sessionID", p.config.SessionID).Msg("MongoDB server authentication successful")
	return serverConn, nil
}

func (p *MongoDBProxy) proxyToServer(client, server net.Conn, errCh chan error) {
	defer func() {
		if r := recover(); r != nil {
			errCh <- fmt.Errorf("panic in proxyToServer: %v", r)
		}
	}()

	for {
		msg, err := ReadMessage(client)
		if err != nil {
			errCh <- err
			return
		}

		// Block non-OP_MSG opcodes — only OP_MSG should flow during the relay phase.
		// We advertised maxWireVersion:17 in our hello, so modern drivers won't send legacy
		// opcodes. But if something unexpected arrives, we block it rather than let it through
		// unlogged. This matches MSSQL's approach of blocking unrecognized packet types.
		if msg.Header.OpCode != OpMsg {
			log.Warn().
				Str("sessionID", p.config.SessionID).
				Int32("opCode", msg.Header.OpCode).
				Msg("Blocked non-OP_MSG opcode (cannot be session recorded)")
			continue
		}

		// Parse for audit logging. If parsing fails, block the message —
		// if we can't log it, we don't let it through. This prevents a crafted
		// message from executing on the server without an audit record.
		sections, parseErr := ParseOpMsgSections(msg.Payload)
		if parseErr != nil {
			log.Warn().
				Str("sessionID", p.config.SessionID).
				Err(parseErr).
				Msg("Blocked OP_MSG that failed to parse (cannot be session recorded)")
			continue
		}

		summary := SummarizeCommand(sections)
		p.mu.Lock()
		p.pendingQuery = &pendingQuery{
			summary:   summary,
			timestamp: time.Now(),
		}
		p.mu.Unlock()

		if err := WriteMessage(server, msg); err != nil {
			errCh <- err
			return
		}
	}
}

func (p *MongoDBProxy) proxyToClient(server, client net.Conn, errCh chan error) {
	defer func() {
		if r := recover(); r != nil {
			errCh <- fmt.Errorf("panic in proxyToClient: %v", r)
		}
	}()

	for {
		msg, err := ReadMessage(server)
		if err != nil {
			errCh <- err
			return
		}

		// Match response with pending query for audit logging
		if msg.Header.OpCode == OpMsg {
			p.mu.Lock()
			pending := p.pendingQuery
			p.pendingQuery = nil
			p.mu.Unlock()

			if pending != nil {
				output := summarizeResponse(msg.Payload)
				p.config.SessionLogger.LogEntry(session.SessionLogEntry{
					Timestamp: pending.timestamp,
					Input:     pending.summary,
					Output:    output,
				})
			}
		}

		if err := WriteMessage(client, msg); err != nil {
			errCh <- err
			return
		}
	}
}

// responseInternalFields are replica set / session metadata fields in server responses
// that are not useful for audit logging.
var responseInternalFields = map[string]bool{
	"$clusterTime":  true,
	"operationTime": true,
	"electionId":    true,
	"setName":       true,
	"setVersion":    true,
	"$configTime":   true,
	"$topologyTime": true,
}

// summarizeResponse serializes the server response as extended JSON for audit logging.
// Unlike the previous implementation that only returned "OK" / "ERROR", this captures
// full response data — including documents returned by find/aggregate, write results (n,
// nModified), and error details. This is important for audit: if a user reads sensitive
// data via db.users.find(), the audit log should show what they actually got back.
func summarizeResponse(payload []byte) string {
	body, err := ParseOpMsgBody(payload)
	if err != nil {
		return "(failed to parse response)"
	}

	elems, err := body.Elements()
	if err != nil {
		return "(failed to read response elements)"
	}

	// Filter out replica set metadata, keep everything relevant to the operation
	filtered := bson.D{}
	for _, elem := range elems {
		if !responseInternalFields[elem.Key()] {
			filtered = append(filtered, bson.E{Key: elem.Key(), Value: elem.Value()})
		}
	}

	jsonBytes, err := bson.MarshalExtJSON(filtered, false, false)
	if err != nil {
		return "(failed to serialize response)"
	}
	return string(jsonBytes)
}
