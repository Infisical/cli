package mongodb

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/mnet"
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
	serverConn *mnet.Connection // Driver's pooled connection
	clientConn net.Conn         // Client TCP stays the same
	logger     session.SessionLogger
	database   string
	maxMsgSize uint32 // From server hello, default 48MB
}

func newBridge(serverConn *mnet.Connection, clientConn net.Conn, logger session.SessionLogger, defaultDB string) *bridge {
	return &bridge{
		serverConn: serverConn,
		clientConn: clientConn,
		logger:     logger,
		database:   defaultDB,
		maxMsgSize: 48 * 1024 * 1024, // 48MB default
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

		// Validate message size before processing
		msgLen := uint32(hdr.MessageLength)
		if msgLen > b.maxMsgSize {
			log.Warn().
				Uint32("msgLen", msgLen).
				Uint32("maxMsgSize", b.maxMsgSize).
				Msg("Client message exceeds max size")
			if err := replyError(b.clientConn, hdr.RequestID,
				fmt.Sprintf("message size %d exceeds maximum %d", msgLen, b.maxMsgSize)); err != nil {
				return fmt.Errorf("failed to send size error: %w", err)
			}
			continue
		}

		log.Debug().
			Int32("opcode", hdr.OpCode).
			Int32("requestID", hdr.RequestID).
			Int32("msgLen", hdr.MessageLength).
			Msg("[WIRE] <- client message")

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
			// Forward unknown opcodes transparently
			if err := b.forwardRaw(ctx, raw); err != nil {
				return err
			}
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
		dbName = b.database
	}

	log.Debug().
		Str("cmd", cmdName).
		Str("db", dbName).
		Uint32("flagBits", msg.FlagBits).
		Bool("moreToCome", msg.FlagBits&flagMoreToCome != 0).
		Msg("[WIRE] <- OP_MSG")

	// Block auth commands — the proxy already authenticated with the server
	if isAuthCommand(cmdName) {
		log.Debug().Str("cmd", cmdName).Msg("[WIRE] -> blocking auth command")
		return replyError(b.clientConn, msg.Header.RequestID,
			"authentication is handled by the proxy")
	}

	// Forward the raw wire message to the server via driver connection
	if err := b.serverConn.Write(ctx, raw); err != nil {
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

	// Read server response via driver connection
	serverBytes, err := b.serverConn.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read server response: %w", err)
	}

	// Parse header from response for logging/detection
	respHdr := parseHeaderFromBytes(serverBytes)

	log.Debug().
		Int32("opcode", respHdr.OpCode).
		Int32("responseTo", respHdr.ResponseTo).
		Int32("msgLen", respHdr.MessageLength).
		Msg("[WIRE] -> server response")

	// Sanitize hello/ismaster responses to prevent the client from attempting
	// authentication through the proxy (we already authed on its behalf).
	if isHelloCommand(cmdName) && respHdr.OpCode == opMsgOpCode {
		if sanitized, sanitizeErr := sanitizeHelloWireMessage(respHdr, serverBytes); sanitizeErr == nil {
			serverBytes = sanitized

			// Extract maxMessageSizeBytes from hello response
			b.updateMaxMsgSize(serverBytes)
		} else {
			log.Warn().Err(sanitizeErr).Msg("Failed to sanitize hello response, forwarding as-is")
		}
	}

	// Log user commands for session recording
	if !isInternalCommand(cmdName) {
		var respBody bson.Raw
		if respHdr.OpCode == opMsgOpCode {
			if respMsg, parseErr := parseOpMsg(respHdr, serverBytes); parseErr == nil {
				respBody = respMsg.Body
			}
		}
		cmdDoc, _ := mergeDocumentSequences(msg.Body, msg.DocumentSequences)
		b.logCommand(cmdName, dbName, cmdDoc, respBody)
	}

	return writeWireMessage(b.clientConn, serverBytes)
}

func (b *bridge) handleOpQuery(ctx context.Context, hdr *wireHeader, raw []byte) error {
	q, err := parseOpQuery(hdr, raw)
	if err != nil {
		return fmt.Errorf("failed to parse OP_QUERY: %w", err)
	}

	cmdName := getCommandName(q.Query)
	log.Debug().
		Str("cmd", cmdName).
		Str("collection", q.Collection).
		Msg("[WIRE] <- OP_QUERY")

	if err := b.serverConn.Write(ctx, raw); err != nil {
		return fmt.Errorf("failed to forward OP_QUERY: %w", err)
	}

	respBytes, err := b.serverConn.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read OP_QUERY response: %w", err)
	}

	return writeWireMessage(b.clientConn, respBytes)
}

// forwardRaw forwards a raw wire message to the server and sends the response back.
func (b *bridge) forwardRaw(ctx context.Context, raw []byte) error {
	if err := b.serverConn.Write(ctx, raw); err != nil {
		return fmt.Errorf("failed to forward raw message: %w", err)
	}
	respBytes, err := b.serverConn.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read raw response: %w", err)
	}
	return writeWireMessage(b.clientConn, respBytes)
}

// replyError sends a MongoDB wire protocol error response to the client.
func replyError(conn net.Conn, requestID int32, msg string) error {
	errDoc, _ := bson.Marshal(bson.D{
		{Key: "ok", Value: int32(0)},
		{Key: "errmsg", Value: msg},
	})
	reply := buildOpMsgReply(requestID, errDoc)
	return writeWireMessage(conn, reply)
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
	reply[20] = 0                                   // Kind 0
	copy(reply[21:], sanitized)

	return reply, nil
}

// updateMaxMsgSize extracts maxMessageSizeBytes from a hello response to
// use for validating incoming message sizes.
func (b *bridge) updateMaxMsgSize(raw []byte) {
	hdr := parseHeaderFromBytes(raw)
	if hdr.OpCode != opMsgOpCode {
		return
	}
	msg, err := parseOpMsg(hdr, raw)
	if err != nil {
		return
	}
	var doc bson.M
	if err := bson.Unmarshal(msg.Body, &doc); err != nil {
		return
	}
	if maxSize, ok := doc["maxMessageSizeBytes"]; ok {
		if size := toUint32(maxSize); size > 0 {
			b.maxMsgSize = size
			log.Debug().Uint32("maxMsgSize", size).Msg("Updated max message size from server hello")
		}
	}
}

// parseHeaderFromBytes parses a wire header from raw message bytes.
func parseHeaderFromBytes(raw []byte) *wireHeader {
	if len(raw) < headerLength {
		return &wireHeader{}
	}
	return &wireHeader{
		MessageLength: int32(binary.LittleEndian.Uint32(raw[0:4])),
		RequestID:     int32(binary.LittleEndian.Uint32(raw[4:8])),
		ResponseTo:    int32(binary.LittleEndian.Uint32(raw[8:12])),
		OpCode:        int32(binary.LittleEndian.Uint32(raw[12:16])),
	}
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

	if err := b.logger.LogEntry(session.SessionLogEntry{
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

func toUint32(v interface{}) uint32 {
	switch n := v.(type) {
	case float64:
		return uint32(n)
	case int32:
		return uint32(n)
	case int64:
		return uint32(n)
	case int:
		return uint32(n)
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
