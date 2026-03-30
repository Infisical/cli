package mongodb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Fields to strip from logged input — protocol noise, not user intent.
// We keep $db so admins can see database switches (e.g. "use prodDB").
var logNoiseFields = []string{
	"$clusterTime",
	"lsid",
	"$readPreference",
	"txnNumber",
	"startTransaction",
	"autocommit",
	"apiVersion",
}

type bridge struct {
	serverConn    net.Conn
	clientConn    net.Conn
	sessionLogger session.SessionLogger
	defaultDB     string
}

func newBridge(serverConn net.Conn, clientConn net.Conn, logger session.SessionLogger, defaultDB string) *bridge {
	return &bridge{
		serverConn:    serverConn,
		clientConn:    clientConn,
		sessionLogger: logger,
		defaultDB:     defaultDB,
	}
}

func (b *bridge) run(ctx context.Context) error {
	bridgeStart := time.Now()                                                                                                                                              // [DIAG-CONNPOOL]
	log.Info().Str("client", b.clientConn.RemoteAddr().String()).Str("server", b.serverConn.RemoteAddr().String()).Msg("[DIAG-CONNPOOL] bridge started, proxying traffic") // [DIAG-CONNPOOL]
	defer func() {                                                                                                                                                         // [DIAG-CONNPOOL]
		log.Info().Dur("lifetime_ms", time.Since(bridgeStart)).Str("client", b.clientConn.RemoteAddr().String()).Msg("[DIAG-CONNPOOL] bridge ended") // [DIAG-CONNPOOL]
	}() // [DIAG-CONNPOOL]

	// Close connections when context is cancelled to unblock blocking reads.
	go func() {
		<-ctx.Done()
		b.clientConn.Close()
		b.serverConn.Close()
	}()

	for {
		hdr, raw, err := readWireMessage(b.clientConn)
		if err != nil {
			if isConnectionClosed(err) {
				log.Debug().Msg("MongoDB client disconnected")
				return nil
			}
			return fmt.Errorf("failed to read client message: %w", err)
		}

		log.Debug().
			Int32("opcode", hdr.OpCode).
			Int32("requestID", hdr.RequestID).
			Int32("msgLen", hdr.MessageLength).
			Msg("[WIRE] <- client message")

		switch hdr.OpCode {
		case opMsgOpCode:
			if err := b.handleOpMsg(hdr, raw); err != nil {
				return err
			}
		case opQueryOpCode:
			if err := b.handleOpQuery(hdr, raw); err != nil {
				return err
			}
		default:
			// Forward unknown opcodes transparently
			if err := b.forwardRaw(raw); err != nil {
				return err
			}
		}
	}
}

func (b *bridge) handleOpMsg(hdr *wireHeader, raw []byte) error {
	msg, err := parseOpMsg(hdr, raw)
	if err != nil {
		return fmt.Errorf("failed to parse OP_MSG: %w", err)
	}

	cmdName := getCommandName(msg.Body)
	dbName := getStringField(msg.Body, "$db")
	if dbName == "" {
		dbName = b.defaultDB
	}

	log.Debug().
		Str("cmd", cmdName).
		Str("db", dbName).
		Uint32("flagBits", msg.FlagBits).
		Bool("moreToCome", msg.FlagBits&flagMoreToCome != 0).
		Msg("[WIRE] <- OP_MSG")

	// Intercept auth commands — the proxy already authenticated with the server
	if isAuthCommand(cmdName) {
		log.Debug().Str("cmd", cmdName).Msg("[WIRE] -> fake auth response")
		return b.handleAuthCommand(msg)
	}

	// Strip "client" metadata from hello/ismaster requests — the proxy already
	// sent the first hello during authenticateWithServer, and MongoDB only
	// allows client metadata in the first hello on a connection.
	if isHelloCommand(cmdName) {
		if sanitized, err := sanitizeHelloRequest(hdr, raw); err == nil {
			raw = sanitized
		}
	}

	// Forward the raw wire message to the server
	if err := writeWireMessage(b.serverConn, raw); err != nil {
		return fmt.Errorf("failed to forward to server: %w", err)
	}

	// moreToCome: server won't send a response
	if msg.FlagBits&flagMoreToCome != 0 {
		log.Debug().Str("cmd", cmdName).Msg("[WIRE] moreToCome set, no response expected")
		if !isInternalCommand(cmdName) {
			cmdDoc, _ := mergeDocumentSequences(msg.Body, msg.DocumentSequences)
			b.logCommand(cmdName, dbName, cmdDoc, nil)
		}
		return nil
	}

	// Read server response
	respHdr, respRaw, err := readWireMessage(b.serverConn)
	if err != nil {
		return fmt.Errorf("failed to read server response: %w", err)
	}

	log.Debug().
		Int32("opcode", respHdr.OpCode).
		Int32("responseTo", respHdr.ResponseTo).
		Int32("msgLen", respHdr.MessageLength).
		Msg("[WIRE] -> server response")

	// Sanitize hello/ismaster responses to prevent the client from attempting
	// authentication through the proxy (we already authed on its behalf).
	if isHelloCommand(cmdName) && respHdr.OpCode == opMsgOpCode {
		if sanitized, err := sanitizeHelloWireMessage(respHdr, respRaw); err == nil {
			respRaw = sanitized
		} else {
			log.Warn().Err(err).Msg("Failed to sanitize hello response, forwarding as-is")
		}
	}

	// Log user commands for session recording
	if !isInternalCommand(cmdName) {
		var respBody bson.Raw
		if respHdr.OpCode == opMsgOpCode {
			if respMsg, parseErr := parseOpMsg(respHdr, respRaw); parseErr == nil {
				respBody = respMsg.Body
			}
		}
		cmdDoc, _ := mergeDocumentSequences(msg.Body, msg.DocumentSequences)
		b.logCommand(cmdName, dbName, cmdDoc, respBody)
	}

	return writeWireMessage(b.clientConn, respRaw)
}

func (b *bridge) handleOpQuery(hdr *wireHeader, raw []byte) error {
	q, err := parseOpQuery(hdr, raw)
	if err != nil {
		return fmt.Errorf("failed to parse OP_QUERY: %w", err)
	}

	cmdName := getCommandName(q.Query)
	log.Debug().
		Str("cmd", cmdName).
		Str("collection", q.Collection).
		Msg("[WIRE] <- OP_QUERY")

	// Strip first-hello-only fields from ismaster/hello OP_QUERY requests.
	// The proxy already sent the first hello during authentication.
	if isHelloCommand(cmdName) {
		if sanitized, err := sanitizeOpQueryHelloRequest(q); err == nil {
			raw = sanitized
		}
	}

	if err := writeWireMessage(b.serverConn, raw); err != nil {
		return fmt.Errorf("failed to forward OP_QUERY: %w", err)
	}

	_, respRaw, err := readWireMessage(b.serverConn)
	if err != nil {
		return fmt.Errorf("failed to read OP_QUERY response: %w", err)
	}

	return writeWireMessage(b.clientConn, respRaw)
}

// forwardRaw forwards a raw wire message to the server and sends the response back.
func (b *bridge) forwardRaw(raw []byte) error {
	if err := writeWireMessage(b.serverConn, raw); err != nil {
		return fmt.Errorf("failed to forward raw message: %w", err)
	}
	_, respRaw, err := readWireMessage(b.serverConn)
	if err != nil {
		return fmt.Errorf("failed to read raw response: %w", err)
	}
	return writeWireMessage(b.clientConn, respRaw)
}

// handleAuthCommand responds with fake success since the proxy handles auth.
func (b *bridge) handleAuthCommand(msg *opMsg) error {
	cmdName := strings.ToLower(getCommandName(msg.Body))

	var resp bson.Raw
	var err error

	switch cmdName {
	case "saslstart", "saslcontinue":
		resp, err = bson.Marshal(bson.D{
			{Key: "ok", Value: 1},
			{Key: "done", Value: true},
			{Key: "conversationId", Value: int32(1)},
			{Key: "payload", Value: primitive.Binary{Data: []byte{}}},
		})
	default:
		resp, err = bson.Marshal(bson.D{
			{Key: "ok", Value: 1},
		})
	}
	if err != nil {
		return fmt.Errorf("failed to marshal auth response: %w", err)
	}

	reply := buildOpMsg(msg.Header.RequestID, resp)
	return writeWireMessage(b.clientConn, reply)
}

// sanitizeOpQueryHelloRequest strips first-hello-only fields from an OP_QUERY
// ismaster/hello request. OP_QUERY format:
// header(16) + flags(4) + collection(null-terminated) + skip(4) + return(4) + query(BSON)
func sanitizeOpQueryHelloRequest(q *opQuery) ([]byte, error) {
	stripped, err := stripFields(q.Query, "client", "compression", "saslSupportedMechs", "speculativeAuthenticate")
	if err != nil {
		return nil, err
	}

	collection := q.Collection
	// header(16) + flags(4) + collection + null(1) + skip(4) + return(4) + doc
	totalLen := headerLength + 4 + len(collection) + 1 + 4 + 4 + len(stripped)
	out := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(out[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(out[4:8], uint32(q.Header.RequestID))
	binary.LittleEndian.PutUint32(out[8:12], uint32(q.Header.ResponseTo))
	binary.LittleEndian.PutUint32(out[12:16], uint32(opQueryOpCode))
	binary.LittleEndian.PutUint32(out[16:20], uint32(q.Flags))
	copy(out[20:], collection)
	pos := 20 + len(collection)
	out[pos] = 0 // null terminator
	pos++
	binary.LittleEndian.PutUint32(out[pos:pos+4], uint32(q.Skip))
	binary.LittleEndian.PutUint32(out[pos+4:pos+8], uint32(q.Return))
	copy(out[pos+8:], stripped)

	return out, nil
}

// sanitizeHelloRequest strips fields from a hello/ismaster request that must
// only appear in the first hello on a connection (which the proxy already sent
// during authentication). See MongoDB spec: "client metadata document may only
// be sent in the first hello".
func sanitizeHelloRequest(hdr *wireHeader, raw []byte) ([]byte, error) {
	msg, err := parseOpMsg(hdr, raw)
	if err != nil {
		return nil, err
	}

	stripped, err := stripFields(msg.Body, "client", "compression", "saslSupportedMechs", "speculativeAuthenticate")
	if err != nil {
		return nil, err
	}

	totalLen := headerLength + 4 + 1 + len(stripped)
	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(out[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(out[4:8], uint32(hdr.RequestID))
	binary.LittleEndian.PutUint32(out[8:12], uint32(hdr.ResponseTo))
	binary.LittleEndian.PutUint32(out[12:16], uint32(opMsgOpCode))
	binary.LittleEndian.PutUint32(out[16:20], msg.FlagBits)
	out[20] = 0 // Kind 0
	copy(out[21:], stripped)

	return out, nil
}

// sanitizeHelloWireMessage strips auth-related fields from a hello response
// to prevent the client from attempting authentication through the proxy.
func sanitizeHelloWireMessage(hdr *wireHeader, raw []byte) ([]byte, error) {
	msg, err := parseOpMsg(hdr, raw)
	if err != nil {
		return nil, err
	}

	var doc bson.M
	if err := bson.Unmarshal(msg.Body, &doc); err != nil {
		return nil, err
	}

	delete(doc, "compression")
	delete(doc, "saslSupportedMechs")
	delete(doc, "speculativeAuthenticate")

	sanitized, err := bson.Marshal(doc)
	if err != nil {
		return nil, err
	}

	// Rebuild the OP_MSG with sanitized body, preserving original header IDs
	totalLen := headerLength + 4 + 1 + len(sanitized)
	reply := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(reply[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(reply[4:8], uint32(hdr.RequestID))
	binary.LittleEndian.PutUint32(reply[8:12], uint32(hdr.ResponseTo))
	binary.LittleEndian.PutUint32(reply[12:16], uint32(opMsgOpCode))
	binary.LittleEndian.PutUint32(reply[16:20], 0) // flagBits
	reply[20] = 0                                  // Kind 0
	copy(reply[21:], sanitized)

	return reply, nil
}

func (b *bridge) logCommand(cmdName, dbName string, command bson.Raw, response bson.Raw) {
	var input string
	if command != nil {
		cleanCmd, err := stripFields(command, logNoiseFields...)
		if err != nil {
			cleanCmd = command
		}
		input = bsonToJSON(cleanCmd)
	}

	output := ""
	if response != nil {
		output = formatResponseSummary(cmdName, response)
	}

	if err := b.sessionLogger.LogEntry(session.SessionLogEntry{
		Timestamp: time.Now(),
		Input:     input,
		Output:    output,
	}); err != nil {
		log.Error().Err(err).
			Str("cmd", cmdName).
			Str("db", dbName).
			Msg("Failed to write MongoDB session log entry")
	}
}

func isAuthCommand(cmdName string) bool {
	switch strings.ToLower(cmdName) {
	case "saslstart", "saslcontinue", "authenticate", "logout":
		return true
	}
	return false
}

func isHelloCommand(cmdName string) bool {
	switch strings.ToLower(cmdName) {
	case "hello", "ismaster":
		return true
	}
	return false
}

// isInternalCommand returns true for protocol-level commands that are not
// user-initiated activity and should be excluded from session logs.
func isInternalCommand(cmdName string) bool {
	switch strings.ToLower(cmdName) {
	case "ismaster", "hello", "ping":
		return true
	}
	return false
}

func bsonToJSON(raw bson.Raw) string {
	if len(raw) == 0 {
		return "{}"
	}
	data, err := bson.MarshalExtJSON(raw, false, false)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func formatResponseSummary(cmdName string, response bson.Raw) string {
	var result bson.M
	if err := bson.Unmarshal(response, &result); err != nil {
		return "ERROR (failed to parse response)"
	}

	if toFloat64(result["ok"]) != 1 {
		errmsg, _ := result["errmsg"].(string)
		if code, ok := result["code"]; ok {
			return fmt.Sprintf("ERROR (%v: %s)", code, errmsg)
		}
		return fmt.Sprintf("ERROR (%s)", errmsg)
	}

	switch strings.ToLower(cmdName) {
	case "find", "aggregate":
		if cursor, ok := result["cursor"].(bson.M); ok {
			if batch, ok := cursor["firstBatch"].(bson.A); ok {
				return fmt.Sprintf("SUCCESS (cursor: %d documents in firstBatch)", len(batch))
			}
		}
	case "getmore":
		if cursor, ok := result["cursor"].(bson.M); ok {
			if batch, ok := cursor["nextBatch"].(bson.A); ok {
				return fmt.Sprintf("SUCCESS (cursor: %d documents in nextBatch)", len(batch))
			}
		}
	case "insert":
		if n, ok := result["n"]; ok {
			return fmt.Sprintf("SUCCESS (n: %v inserted)", n)
		}
	case "update":
		if n, ok := result["n"]; ok {
			return fmt.Sprintf("SUCCESS (n: %v, nModified: %v)", n, result["nModified"])
		}
	case "delete":
		if n, ok := result["n"]; ok {
			return fmt.Sprintf("SUCCESS (n: %v deleted)", n)
		}
	case "count", "countdocuments":
		if n, ok := result["n"]; ok {
			return fmt.Sprintf("SUCCESS (n: %v)", n)
		}
	}

	return "SUCCESS"
}

// isConnectionClosed returns true for errors that indicate a normal client disconnect.
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}
