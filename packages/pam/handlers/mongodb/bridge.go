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
// We keep $db so admins can see which database a command targets.
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

	// Strip fields from hello requests that are incompatible with proxied
	// (reused) connections — see stripHelloFields for the full list.
	if isHelloCommand(cmdName) {
		if sanitized, err := sanitizeHelloRequest(hdr, raw); err == nil {
			raw = sanitized
		} else {
			log.Warn().Err(err).Msg("Failed to sanitize hello request, forwarding as-is")
		}
	}

	// Strip exhaustAllowed — proxy uses single request/response semantics.
	raw = clearExhaustAllowed(raw)

	// Forward the raw wire message to the server via driver connection
	if err := b.serverConn.Write(ctx, raw); err != nil {
		return fmt.Errorf("failed to forward to server: %w", err)
	}

	// moreToCome on client request: no server response expected
	if msg.FlagBits&flagMoreToCome != 0 {
		log.Debug().Str("cmd", cmdName).Msg("[WIRE] moreToCome set, no response expected")
		if !isInternalCommand(cmdName) {
			cmdDoc, _ := mergeDocumentSequences(msg.Body, msg.DocumentSequences)
			b.logCommand(cmdName, dbName, cmdDoc, nil)
		}
		return nil
	}

	// Read server response. Drain any moreToCome continuations to prevent
	// leftover data from desynchronizing the connection.
	const maxDrainIterations = 1000
	serverBytes, err := b.serverConn.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read server response: %w", err)
	}
	for i := 0; hasMoreToCome(serverBytes); i++ {
		if i >= maxDrainIterations {
			log.Warn().Str("cmd", cmdName).Int("iterations", i).
				Msg("[WIRE] moreToCome drain exceeded limit, closing connection")
			return fmt.Errorf("moreToCome drain exceeded %d iterations", maxDrainIterations)
		}
		log.Debug().Str("cmd", cmdName).Msg("[WIRE] draining moreToCome continuation from server")
		serverBytes, err = b.serverConn.Read(ctx)
		if err != nil {
			return fmt.Errorf("failed to drain moreToCome response: %w", err)
		}
	}

	// Parse header from response for logging/detection
	respHdr := parseHeaderFromBytes(serverBytes)

	log.Debug().
		Int32("opcode", respHdr.OpCode).
		Int32("responseTo", respHdr.ResponseTo).
		Int32("msgLen", respHdr.MessageLength).
		Msg("[WIRE] -> server response")

	// Sanitize hello/ismaster responses — remove auth and topology fields
	// since authentication is handled by the proxy.
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

	// Clear moreToCome flag — proxy enforces single request/response semantics.
	clearMoreToCome(serverBytes)

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

	// Convert OP_QUERY hello/isMaster to OP_MSG — OP_QUERY is removed in
	// MongoDB 8.0+ and incompatible with proxied connections.
	if isHelloCommand(cmdName) {
		opMsg, err := convertOpQueryToOpMsg(q)
		if err != nil {
			return fmt.Errorf("failed to convert OP_QUERY to OP_MSG: %w", err)
		}

		if err := b.serverConn.Write(ctx, opMsg); err != nil {
			return fmt.Errorf("failed to forward converted hello: %w", err)
		}

		respBytes, err := b.serverConn.Read(ctx)
		if err != nil {
			return fmt.Errorf("failed to read hello response: %w", err)
		}

		// Sanitize hello response (strip auth-related fields and topologyVersion)
		// before converting to OP_REPLY, same as the OP_MSG path.
		respHdr := parseHeaderFromBytes(respBytes)
		if respHdr.OpCode == opMsgOpCode {
			if sanitized, sanitizeErr := sanitizeHelloWireMessage(respHdr, respBytes); sanitizeErr == nil {
				respBytes = sanitized
			} else {
				log.Warn().Err(sanitizeErr).Msg("Failed to sanitize OP_QUERY hello response, forwarding as-is")
			}
		}

		// Convert OP_MSG response back to OP_REPLY for the client
		reply, err := convertOpMsgResponseToOpReply(q.Header.RequestID, respBytes)
		if err != nil {
			return fmt.Errorf("failed to convert response to OP_REPLY: %w", err)
		}

		return writeWireMessage(b.clientConn, reply)
	}

	// Non-hello OP_QUERY: forward as-is
	if err := b.serverConn.Write(ctx, raw); err != nil {
		return fmt.Errorf("failed to forward OP_QUERY: %w", err)
	}

	respBytes, err := b.serverConn.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read OP_QUERY response: %w", err)
	}

	clearMoreToCome(respBytes)
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
	clearMoreToCome(respBytes)
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

// stripHelloFields removes fields from a hello command that are incompatible
// with proxied connections, preserving key order so the command name stays first.
func stripHelloFields(raw bson.Raw) (bson.Raw, error) {
	var doc bson.D
	if err := bson.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}

	strip := map[string]bool{
		"client":          true,
		"compression":     true,
		"topologyVersion": true,
		"maxAwaitTimeMS":  true,
	}

	result := make(bson.D, 0, len(doc))
	for _, elem := range doc {
		if !strip[elem.Key] {
			result = append(result, elem)
		}
	}

	return bson.Marshal(result)
}

// convertOpQueryToOpMsg converts a legacy OP_QUERY hello/isMaster to OP_MSG.
// MongoDB 8.0+ removed OP_QUERY support, so we must convert before forwarding.
func convertOpQueryToOpMsg(q *opQuery) ([]byte, error) {
	sanitized, err := stripHelloFields(q.Query)
	if err != nil {
		return nil, err
	}

	// Add $db field required by OP_MSG (extract from collection: "admin.$cmd" → "admin")
	db := q.Collection
	if idx := strings.Index(db, "."); idx != -1 {
		db = db[:idx]
	}

	var doc bson.D
	if err := bson.Unmarshal(sanitized, &doc); err != nil {
		return nil, err
	}
	doc = append(doc, bson.E{Key: "$db", Value: db})

	body, err := bson.Marshal(doc)
	if err != nil {
		return nil, err
	}

	return packOpMsg(q.Header.RequestID, q.Header.ResponseTo, body), nil
}

// convertOpMsgResponseToOpReply wraps an OP_MSG response body as an OP_REPLY
// so the client that sent an OP_QUERY gets the expected response format.
func convertOpMsgResponseToOpReply(responseTo int32, serverBytes []byte) ([]byte, error) {
	hdr := parseHeaderFromBytes(serverBytes)
	if hdr.OpCode != opMsgOpCode {
		// Already an OP_REPLY or other format, return as-is
		return serverBytes, nil
	}
	msg, err := parseOpMsg(hdr, serverBytes)
	if err != nil {
		return nil, err
	}

	return buildOpReply(responseTo, msg.Body), nil
}

// sanitizeHelloRequest strips fields from a hello request that are incompatible
// with proxied connections.
func sanitizeHelloRequest(hdr *wireHeader, raw []byte) ([]byte, error) {
	msg, err := parseOpMsg(hdr, raw)
	if err != nil {
		return nil, err
	}

	sanitized, err := stripHelloFields(msg.Body)
	if err != nil {
		return nil, err
	}

	return packOpMsg(hdr.RequestID, hdr.ResponseTo, sanitized), nil
}

// sanitizeHelloWireMessage strips auth and topology fields from a hello
// response since authentication is handled by the proxy.
func sanitizeHelloWireMessage(hdr *wireHeader, raw []byte) ([]byte, error) {
	msg, err := parseOpMsg(hdr, raw)
	if err != nil {
		return nil, err
	}

	// bson.D preserves field order (bson.M would randomize it).
	var doc bson.D
	if err := bson.Unmarshal(msg.Body, &doc); err != nil {
		return nil, err
	}

	strip := map[string]bool{
		"compression":             true,
		"saslSupportedMechs":      true,
		"speculativeAuthenticate": true,
		"topologyVersion":         true, // Incompatible with request/response proxy
	}

	result := make(bson.D, 0, len(doc))
	for _, elem := range doc {
		if !strip[elem.Key] {
			result = append(result, elem)
		}
	}

	sanitized, err := bson.Marshal(result)
	if err != nil {
		return nil, err
	}

	return packOpMsg(hdr.RequestID, hdr.ResponseTo, sanitized), nil
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

// hasMoreToCome returns true if the raw wire message is an OP_MSG with the
// moreToCome flag set, indicating the server will send additional messages.
func hasMoreToCome(raw []byte) bool {
	if len(raw) < headerLength+4 {
		return false
	}
	opcode := int32(binary.LittleEndian.Uint32(raw[12:16]))
	if opcode != opMsgOpCode {
		return false
	}
	flags := binary.LittleEndian.Uint32(raw[headerLength : headerLength+4])
	return flags&flagMoreToCome != 0
}

// clearExhaustAllowed clears the exhaustAllowed flag (bit 16) from an OP_MSG's
// flagBits so the server won't use exhaust cursors (moreToCome responses).
func clearExhaustAllowed(raw []byte) []byte {
	if len(raw) < headerLength+4 {
		return raw
	}
	flags := binary.LittleEndian.Uint32(raw[headerLength : headerLength+4])
	if flags&flagExhaustAllowed != 0 {
		flags &^= flagExhaustAllowed
		binary.LittleEndian.PutUint32(raw[headerLength:headerLength+4], flags)
	}
	return raw
}

// clearMoreToCome clears the moreToCome flag (bit 1) from an OP_MSG response.
// The proxy does single request/response — the client must never see moreToCome.
func clearMoreToCome(raw []byte) {
	if len(raw) < headerLength+4 {
		return
	}
	opcode := int32(binary.LittleEndian.Uint32(raw[12:16]))
	if opcode != opMsgOpCode {
		return
	}
	flags := binary.LittleEndian.Uint32(raw[headerLength : headerLength+4])
	if flags&flagMoreToCome != 0 {
		flags &^= flagMoreToCome
		binary.LittleEndian.PutUint32(raw[headerLength:headerLength+4], flags)
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
