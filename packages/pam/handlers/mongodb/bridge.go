package mongodb

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

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
			return fmt.Errorf("failed to read client message: %w", err)
		}

		msg, err := parseOpMsg(hdr, raw)
		if err != nil {
			return fmt.Errorf("failed to parse OP_MSG: %w", err)
		}

		cmdName := getCommandName(msg.Body)
		dbName := getStringField(msg.Body, "$db")
		if dbName == "" {
			dbName = b.defaultDB
		}

		// Intercept auth commands — respond with fake success
		if isAuthCommand(cmdName) {
			if err := b.handleAuthCommand(msg); err != nil {
				return fmt.Errorf("failed to handle auth command: %w", err)
			}
			continue
		}

		// Merge Kind 1 document sequences into the body for RunCommand
		merged, err := mergeDocumentSequences(msg.Body, msg.DocumentSequences)
		if err != nil {
			return fmt.Errorf("failed to merge document sequences: %w", err)
		}

		// Strip $db — RunCommand adds it from the Database() call
		stripped, err := stripFields(merged, "$db")
		if err != nil {
			return fmt.Errorf("failed to strip $db: %w", err)
		}

		// Execute on the real server
		rawResp, cmdErr := b.client.Database(dbName).RunCommand(ctx, stripped).Raw()

		if rawResp == nil {
			// Network / context error — no response from server
			if cmdErr != nil {
				log.Error().Err(cmdErr).Str("cmd", cmdName).Msg("RunCommand failed with no response")
				return fmt.Errorf("RunCommand failed: %w", cmdErr)
			}
			return fmt.Errorf("RunCommand returned nil response")
		}

		// For hello/isMaster, strip fields that would cause the client
		// to attempt compression or authentication through us
		if isHelloCommand(cmdName) {
			rawResp = sanitizeHelloResponse(rawResp)
		}

		// Session recording
		b.logCommand(cmdName, dbName, merged, rawResp)

		// Send response back to client
		reply := buildOpMsgReply(msg.Header.RequestID, rawResp)
		if err := writeWireMessage(b.clientConn, reply); err != nil {
			return fmt.Errorf("failed to write response to client: %w", err)
		}
	}
}

// isAuthCommand returns true for commands we intercept to fake authentication.
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

// handleAuthCommand responds to authentication commands with fake success,
// since the proxy authenticates to the real server on behalf of the user.
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
	default: // authenticate, logout
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

// logCommand records a command and its response summary to the session log.
func (b *bridge) logCommand(cmdName, dbName string, command bson.Raw, response bson.Raw) {
	input := bsonToJSON(command)
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

// bsonToJSON converts a raw BSON document to a JSON string for logging.
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

// formatResponseSummary produces a human-readable summary of a command response.
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
