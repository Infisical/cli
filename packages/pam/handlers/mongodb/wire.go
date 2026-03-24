package mongodb

import (
	"encoding/binary"
	"fmt"
	"io"

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
		if pos >= sectionEnd {
			break
		}
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

// SummarizeCommand returns a short human-readable summary of a MongoDB command
// for audit logging. Example: "find users {age: {$gt: 25}}".
func SummarizeCommand(body bson.Raw) string {
	cmdName := ExtractCommandName(body)
	if cmdName == "" {
		return "(unknown command)"
	}

	// For the command value, try to get the collection name (for CRUD commands it's the first value)
	elems, _ := body.Elements()
	if len(elems) == 0 {
		return cmdName
	}

	// The first element's value is often the collection name (string) for CRUD commands
	firstVal := elems[0].Value()
	if firstVal.Type == bson.TypeString {
		collection := firstVal.StringValue()
		// Build a summary from remaining fields (skip $db and lsid which are metadata)
		summary := fmt.Sprintf("%s %s", cmdName, collection)
		for _, elem := range elems[1:] {
			key := elem.Key()
			if key == "$db" || key == "lsid" || key == "$clusterTime" || key == "apiVersion" {
				continue
			}
			summary += fmt.Sprintf(" {%s: ...}", key)
			// Cap summary length to keep audit logs readable
			if len(summary) > 4096 {
				summary = summary[:4096] + "..."
				break
			}
		}
		return summary
	}

	return cmdName
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
