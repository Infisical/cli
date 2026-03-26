package mongodb

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
)

// MongoDB wire protocol constants.
// Reference: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
const (
	HeaderSize = 16 // 4 fields × 4 bytes each: messageLength, requestID, responseTo, opCode

	// OpCodes
	OpReply = 1    // Legacy server reply (deprecated but still used for legacy ismaster)
	OpQuery = 2004 // Legacy client query (deprecated but some drivers use it for initial handshake)
	OpMsg   = 2013 // Modern message format (MongoDB 3.6+), used for all commands

	// OP_MSG flag bits
	FlagChecksumPresent = 1 << 0 // Message includes a CRC-32C checksum (4 trailing bytes)
	FlagMoreToCome      = 1 << 1 // Sender will send another message without waiting for a reply

	// OP_MSG section kinds
	SectionBody             = 0 // Single BSON document (the command body)
	SectionDocumentSequence = 1 // Named sequence of BSON documents (for bulk operations)

	// Safety limits
	MaxMessageSize = 48 * 1024 * 1024 // 48MB, matches MongoDB's default maxMessageSizeBytes
	MinMessageSize = HeaderSize + 4   // Header + at least flagBits for OP_MSG
)

// MongoMessage represents a single MongoDB wire protocol message.
type MongoMessage struct {
	Header  MsgHeader
	Payload []byte // Everything after the 16-byte header
}

// MsgHeader is the standard 16-byte MongoDB wire protocol message header.
type MsgHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

// ReadMessage reads a complete MongoDB wire protocol message from the reader.
func ReadMessage(r io.Reader) (*MongoMessage, error) {
	var hdr MsgHeader
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	if hdr.MessageLength < HeaderSize {
		return nil, fmt.Errorf("invalid message length %d (minimum is %d)", hdr.MessageLength, HeaderSize)
	}
	if hdr.MessageLength > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", hdr.MessageLength, MaxMessageSize)
	}

	payloadLen := hdr.MessageLength - HeaderSize
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read payload (%d bytes): %w", payloadLen, err)
	}

	return &MongoMessage{Header: hdr, Payload: payload}, nil
}

// WriteMessage writes a complete MongoDB wire protocol message to the writer.
func WriteMessage(w io.Writer, msg *MongoMessage) error {
	if err := binary.Write(w, binary.LittleEndian, &msg.Header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := w.Write(msg.Payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// ParseOpMsgBody extracts the body document (section kind 0) from an OP_MSG payload.
// The payload layout is: [4 bytes flagBits] [sections...] [optional 4 bytes checksum].
func ParseOpMsgBody(payload []byte) (bson.Raw, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("OP_MSG payload too short: %d bytes", len(payload))
	}

	flagBits := binary.LittleEndian.Uint32(payload[:4])
	hasChecksum := flagBits&FlagChecksumPresent != 0

	// Determine how many bytes of sections we have (exclude trailing checksum if present)
	sectionEnd := len(payload)
	if hasChecksum {
		sectionEnd -= 4
	}

	pos := 4 // Skip flagBits
	for pos < sectionEnd {
		kind := payload[pos]
		pos++

		switch kind {
		case SectionBody:
			// Kind 0: a single BSON document. The first 4 bytes of the doc are its length.
			if pos+4 > sectionEnd {
				return nil, fmt.Errorf("section body truncated at offset %d", pos)
			}
			docLen := int(binary.LittleEndian.Uint32(payload[pos : pos+4]))
			if docLen < 5 || pos+docLen > sectionEnd {
				return nil, fmt.Errorf("invalid BSON document length %d at offset %d", docLen, pos)
			}
			return bson.Raw(payload[pos : pos+docLen]), nil

		case SectionDocumentSequence:
			// Kind 1: length-prefixed sequence of documents. Skip it — we only need the body.
			if pos+4 > sectionEnd {
				return nil, fmt.Errorf("section document sequence truncated at offset %d", pos)
			}
			seqLen := int(binary.LittleEndian.Uint32(payload[pos : pos+4]))
			if seqLen < 4 || pos+seqLen > sectionEnd {
				return nil, fmt.Errorf("invalid document sequence length %d at offset %d", seqLen, pos)
			}
			pos += seqLen

		default:
			return nil, fmt.Errorf("unknown OP_MSG section kind %d at offset %d", kind, pos-1)
		}
	}

	return nil, fmt.Errorf("no body section (kind 0) found in OP_MSG")
}

// OpMsgSections holds all parsed sections from an OP_MSG payload.
type OpMsgSections struct {
	Body         bson.Raw
	DocSequences map[string][]bson.Raw // identifier -> documents (used by bulk ops like insertMany)
}

// ParseOpMsgSections extracts all sections from an OP_MSG payload.
// Unlike ParseOpMsgBody, this also parses kind-1 document sequence sections so that
// the actual documents in bulk operations (insert, update, delete) are available for logging.
func ParseOpMsgSections(payload []byte) (*OpMsgSections, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("OP_MSG payload too short: %d bytes", len(payload))
	}

	flagBits := binary.LittleEndian.Uint32(payload[:4])
	hasChecksum := flagBits&FlagChecksumPresent != 0

	sectionEnd := len(payload)
	if hasChecksum {
		sectionEnd -= 4
	}

	sections := &OpMsgSections{
		DocSequences: make(map[string][]bson.Raw),
	}

	pos := 4 // Skip flagBits
	for pos < sectionEnd {
		kind := payload[pos]
		pos++

		switch kind {
		case SectionBody:
			if pos+4 > sectionEnd {
				return nil, fmt.Errorf("section body truncated at offset %d", pos)
			}
			docLen := int(binary.LittleEndian.Uint32(payload[pos : pos+4]))
			if docLen < 5 || pos+docLen > sectionEnd {
				return nil, fmt.Errorf("invalid BSON document length %d at offset %d", docLen, pos)
			}
			sections.Body = bson.Raw(payload[pos : pos+docLen])
			pos += docLen

		case SectionDocumentSequence:
			// Kind-1 layout: [4 bytes total sequence length] [null-terminated identifier] [BSON docs...]
			if pos+4 > sectionEnd {
				return nil, fmt.Errorf("section document sequence truncated at offset %d", pos)
			}
			seqLen := int(binary.LittleEndian.Uint32(payload[pos : pos+4]))
			if seqLen < 5 || pos+seqLen > sectionEnd {
				return nil, fmt.Errorf("invalid document sequence length %d at offset %d", seqLen, pos)
			}
			seqEnd := pos + seqLen
			pos += 4 // skip length field

			// Read null-terminated identifier (e.g., "documents", "updates", "deletes")
			identStart := pos
			for pos < seqEnd && payload[pos] != 0 {
				pos++
			}
			if pos >= seqEnd {
				return nil, fmt.Errorf("document sequence missing null terminator for identifier")
			}
			identifier := string(payload[identStart:pos])
			pos++ // skip null byte

			// Read BSON documents until seqEnd
			var docs []bson.Raw
			for pos < seqEnd {
				if pos+4 > seqEnd {
					break
				}
				docLen := int(binary.LittleEndian.Uint32(payload[pos : pos+4]))
				if docLen < 5 || pos+docLen > seqEnd {
					break
				}
				docs = append(docs, bson.Raw(payload[pos:pos+docLen]))
				pos += docLen
			}
			sections.DocSequences[identifier] = docs

		default:
			return nil, fmt.Errorf("unknown OP_MSG section kind %d at offset %d", kind, pos-1)
		}
	}

	if sections.Body == nil {
		return nil, fmt.Errorf("no body section (kind 0) found in OP_MSG")
	}

	return sections, nil
}

// BuildOpMsg builds a complete MongoDB OP_MSG wire message from a BSON command document.
func BuildOpMsg(requestID, responseTo int32, doc bson.D) ([]byte, error) {
	docBytes, err := bson.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal BSON: %w", err)
	}

	// Layout: [header 16] [flagBits 4] [kind 1] [document N]
	msgLen := int32(HeaderSize + 4 + 1 + len(docBytes))

	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(OpMsg))
	binary.LittleEndian.PutUint32(buf[16:20], 0) // flagBits = 0
	buf[20] = SectionBody                        // kind = 0
	copy(buf[21:], docBytes)

	return buf, nil
}

// ExtractCommandName returns the first key from a BSON document, which is the
// MongoDB command name (e.g., "find", "insert", "aggregate", "hello").
func ExtractCommandName(body bson.Raw) string {
	elems, err := body.Elements()
	if err != nil || len(elems) == 0 {
		return ""
	}
	return elems[0].Key()
}

// internalFields are MongoDB session/cluster metadata fields that add noise to audit logs.
// Note: $db is intentionally NOT in this list — it shows which database a command targets,
// which is critical for audit (a user could query a different database than expected).
var internalFields = map[string]bool{
	"lsid":            true,
	"$clusterTime":    true,
	"apiVersion":      true,
	"$readPreference": true,
	"txnNumber":       true,
	"autocommit":      true,
}

// SummarizeCommand returns a human-readable audit log entry for a MongoDB command.
//
// Format: "<command> <collection> <body fields as JSON> [<seqName>: [<docs as JSON>]]"
// Example: `insert students {"ordered":true} documents: [{"name":"Amit","age":20,...}, ...]`
//
// Document sequences (kind-1 OP_MSG sections) carry the actual documents for bulk operations
// like insertMany — these are parsed separately and included here so the audit log contains
// the real data, not just field names.
func SummarizeCommand(sections *OpMsgSections) string {
	body := sections.Body
	cmdName := ExtractCommandName(body)
	if cmdName == "" {
		return "(unknown command)"
	}

	elems, _ := body.Elements()
	if len(elems) == 0 {
		return cmdName
	}

	// The first element's value is the collection name for CRUD commands (find, insert, etc.)
	collection := ""
	if firstVal := elems[0].Value(); firstVal.Type == bson.TypeString {
		collection = firstVal.StringValue()
	}

	// Collect non-internal body fields with their actual values
	bodyDoc := bson.D{}
	for _, elem := range elems[1:] {
		if !internalFields[elem.Key()] {
			bodyDoc = append(bodyDoc, bson.E{Key: elem.Key(), Value: elem.Value()})
		}
	}

	var parts []string
	parts = append(parts, cmdName)
	if collection != "" {
		parts = append(parts, collection)
	}
	if len(bodyDoc) > 0 {
		if jsonBytes, err := bson.MarshalExtJSON(bodyDoc, false, false); err == nil {
			parts = append(parts, string(jsonBytes))
		}
	}

	// Add document sequences — these hold the actual documents for bulk operations
	// (e.g., the inserted documents in insertMany, update specs in updateMany)
	for seqID, docs := range sections.DocSequences {
		docStrs := make([]string, 0, len(docs))
		for _, doc := range docs {
			if jsonBytes, err := bson.MarshalExtJSON(doc, false, false); err == nil {
				docStrs = append(docStrs, string(jsonBytes))
			}
		}
		if len(docStrs) > 0 {
			parts = append(parts, fmt.Sprintf("%s: [%s]", seqID, strings.Join(docStrs, ", ")))
		}
	}

	return strings.Join(parts, " ")
}

// BuildOpReply builds a legacy OP_REPLY message (opCode 1) for responding to OP_QUERY.
// Used for legacy driver hello/ismaster handshake.
func BuildOpReply(requestID, responseTo int32, doc bson.D) ([]byte, error) {
	docBytes, err := bson.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal BSON: %w", err)
	}

	// OP_REPLY layout: [header 16] [responseFlags 4] [cursorID 8] [startingFrom 4] [numberReturned 4] [documents...]
	msgLen := int32(HeaderSize + 4 + 8 + 4 + 4 + len(docBytes))

	buf := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(OpReply))
	// responseFlags = 0, cursorID = 0, startingFrom = 0
	binary.LittleEndian.PutUint32(buf[32:36], 1) // numberReturned = 1
	copy(buf[36:], docBytes)

	return buf, nil
}

// ParseOpQueryBody extracts the query document from a legacy OP_QUERY payload.
// OP_QUERY layout: [flags 4] [fullCollectionName cstring] [numberToSkip 4] [numberToReturn 4] [query document]
func ParseOpQueryBody(payload []byte) (bson.Raw, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("OP_QUERY payload too short: %d bytes", len(payload))
	}

	pos := 4 // Skip flags

	// Skip fullCollectionName (null-terminated string)
	for pos < len(payload) && payload[pos] != 0 {
		pos++
	}
	if pos >= len(payload) {
		return nil, fmt.Errorf("OP_QUERY missing null terminator for collection name")
	}
	pos++ // Skip the null byte

	// Skip numberToSkip (4 bytes) and numberToReturn (4 bytes)
	pos += 8
	if pos+4 > len(payload) {
		return nil, fmt.Errorf("OP_QUERY payload truncated before query document")
	}

	docLen := int(binary.LittleEndian.Uint32(payload[pos : pos+4]))
	if docLen < 5 || pos+docLen > len(payload) {
		return nil, fmt.Errorf("invalid BSON document length %d in OP_QUERY", docLen)
	}

	return bson.Raw(payload[pos : pos+docLen]), nil
}
