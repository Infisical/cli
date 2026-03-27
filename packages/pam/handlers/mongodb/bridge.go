package mongodb

import (
	"context"
	"encoding/json"
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
	"go.mongodb.org/mongo-driver/mongo"
)

// Fields that the mongo.Client's RunCommand adds automatically.
// We must strip these from every client command to avoid BSON duplicate-field errors.
var driverManagedFields = []string{
	"$db",
	"lsid",
	"$clusterTime",
	"$readPreference",
	"txnNumber",
	"startTransaction",
	"autocommit",
}

// Fields to strip from logged input — driver/protocol noise, not user intent.
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

// Fields to strip from hello/isMaster commands before forwarding via RunCommand.
// - client, compression, saslSupportedMechs, speculativeAuthenticate: only allowed
//   in the first hello on a connection (our mongo.Client already sent these).
// - topologyVersion, maxAwaitTimeMS: used for monitoring long-polls. If forwarded,
//   the server blocks for up to maxAwaitTimeMS (typically 10s), stalling the bridge
//   and causing mongosh to mark the server as unknown. Stripping these makes the
//   server respond immediately.
var helloFieldsToStrip = []string{
	"client",
	"compression",
	"saslSupportedMechs",
	"speculativeAuthenticate",
	"topologyVersion",
	"maxAwaitTimeMS",
}

type bridge struct {
	client        *mongo.Client
	clientConn    net.Conn
	sessionLogger session.SessionLogger
	defaultDB     string
}

func newBridge(client *mongo.Client, clientConn net.Conn, logger session.SessionLogger, defaultDB string) *bridge {
	return &bridge{
		client:        client,
		clientConn:    clientConn,
		sessionLogger: logger,
		defaultDB:     defaultDB,
	}
}

func (b *bridge) run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

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
			Msg("[WIRE] ← client message")

		switch hdr.OpCode {
		case opMsgOpCode:
			if err := b.handleOpMsg(ctx, hdr, raw); err != nil {
				return err
			}
		case opQueryOpCode:
			if err := b.handleOpQuery(ctx, hdr, raw); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported opcode %d", hdr.OpCode)
		}
	}
}

func (b *bridge) handleOpMsg(ctx context.Context, hdr *wireHeader, raw []byte) error {
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
		Int("docSequences", len(msg.DocumentSequences)).
		Msg("[WIRE] ← OP_MSG")

	if isAuthCommand(cmdName) {
		log.Debug().Str("cmd", cmdName).Msg("[WIRE] → fake auth response")
		return b.handleAuthCommand(msg)
	}

	// Merge Kind 1 document sequences into the body
	cmdDoc, err := mergeDocumentSequences(msg.Body, msg.DocumentSequences)
	if err != nil {
		return fmt.Errorf("failed to merge document sequences: %w", err)
	}

	// moreToCome (bit 1): the client will send more messages before expecting
	// a response. Execute the command for its side-effects but do NOT reply.
	if msg.FlagBits&flagMoreToCome != 0 {
		log.Debug().Str("cmd", cmdName).Msg("[WIRE] moreToCome set, executing without response")
		_, _ = b.executeAndLog(ctx, cmdName, dbName, cmdDoc)
		return nil // read next message without responding
	}

	rawResp, err := b.executeAndLog(ctx, cmdName, dbName, cmdDoc)
	if err != nil {
		log.Error().Err(err).Str("cmd", cmdName).Msg("[WIRE] executeAndLog failed")
		return err
	}

	reply := buildOpMsgReply(msg.Header.RequestID, rawResp)
	log.Debug().
		Str("cmd", cmdName).
		Int("respBsonLen", len(rawResp)).
		Int("replyWireLen", len(reply)).
		Int32("responseTo", msg.Header.RequestID).
		Msg("[WIRE] → OP_MSG response")
	return writeWireMessage(b.clientConn, reply)
}

func (b *bridge) handleOpQuery(ctx context.Context, hdr *wireHeader, raw []byte) error {
	q, err := parseOpQuery(hdr, raw)
	if err != nil {
		return fmt.Errorf("failed to parse OP_QUERY: %w", err)
	}

	cmdName := getCommandName(q.Query)
	dbName := dbFromCollection(q.Collection)
	if dbName == "" {
		dbName = b.defaultDB
	}

	log.Debug().
		Str("cmd", cmdName).
		Str("db", dbName).
		Str("collection", q.Collection).
		Msg("[WIRE] ← OP_QUERY")

	rawResp, err := b.executeAndLog(ctx, cmdName, dbName, q.Query)
	if err != nil {
		log.Error().Err(err).Str("cmd", cmdName).Msg("[WIRE] OP_QUERY failed")
		return err
	}

	reply := buildOpReply(q.Header.RequestID, rawResp)
	log.Debug().
		Str("cmd", cmdName).
		Int("respBsonLen", len(rawResp)).
		Int("replyWireLen", len(reply)).
		Msg("[WIRE] → OP_REPLY response")
	return writeWireMessage(b.clientConn, reply)
}

// executeAndLog strips driver-managed fields, executes via RunCommand,
// sanitizes hello responses, and records the command to the session log.
func (b *bridge) executeAndLog(ctx context.Context, cmdName, dbName string, cmdDoc bson.Raw) (bson.Raw, error) {
	// Strip all fields that the driver adds automatically to avoid duplicates.
	fieldsToStrip := append([]string{}, driverManagedFields...)
	if isHelloCommand(cmdName) {
		fieldsToStrip = append(fieldsToStrip, helloFieldsToStrip...)
	}

	execDoc, err := stripFields(cmdDoc, fieldsToStrip...)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare command for execution: %w", err)
	}

	rawResp, cmdErr := b.client.Database(dbName).RunCommand(ctx, execDoc).Raw()

	log.Debug().
		Str("cmd", cmdName).
		Bool("hasResp", rawResp != nil).
		Bool("hasErr", cmdErr != nil).
		Int("respBytes", len(rawResp)).
		Msg("[WIRE] RunCommand result")

	if rawResp == nil {
		if cmdErr != nil {
			log.Error().Err(cmdErr).Str("cmd", cmdName).Msg("RunCommand failed with no response")
			return nil, fmt.Errorf("RunCommand failed: %w", cmdErr)
		}
		return nil, fmt.Errorf("RunCommand returned nil response")
	}

	if isHelloCommand(cmdName) {
		rawResp = sanitizeHelloResponse(rawResp)
	}

	if !isInternalCommand(cmdName) {
		b.logCommand(cmdName, dbName, cmdDoc, rawResp)
	}
	return rawResp, nil
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

	reply := buildOpMsgReply(msg.Header.RequestID, resp)
	return writeWireMessage(b.clientConn, reply)
}

// sanitizeHelloResponse strips fields that would make the client attempt
// compression or authentication through the proxy.
func sanitizeHelloResponse(raw bson.Raw) bson.Raw {
	var doc bson.M
	if err := bson.Unmarshal(raw, &doc); err != nil {
		return raw
	}

	delete(doc, "compression")
	delete(doc, "saslSupportedMechs")
	delete(doc, "speculativeAuthenticate")

	sanitized, err := bson.Marshal(doc)
	if err != nil {
		return raw
	}
	return sanitized
}

func (b *bridge) logCommand(cmdName, dbName string, command bson.Raw, response bson.Raw) {
	cleanCmd, err := stripFields(command, logNoiseFields...)
	if err != nil {
		cleanCmd = command
	}
	input := bsonToJSON(cleanCmd)
	output := formatResponseSummary(cmdName, response)

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

func bsonToJSON(raw bson.Raw) string {
	if len(raw) == 0 {
		return "{}"
	}
	var m bson.M
	if err := bson.Unmarshal(raw, &m); err != nil {
		return "{}"
	}
	data, err := json.Marshal(m)
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

func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case int:
		return float64(n)
	default:
		return 0
	}
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
