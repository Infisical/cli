package mongodb

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"go.mongodb.org/mongo-driver/bson"
)

const (
	opQueryOpCode  int32 = 2004
	opMsgOpCode    int32 = 2013
	headerLength         = 16
	maxMessageSize       = 48 * 1024 * 1024 // 48MB

	// OP_MSG flag bits
	flagChecksumPresent uint32 = 1 << 0  // Message includes a trailing checksum
	flagMoreToCome      uint32 = 1 << 1  // Sender will send more messages (no response expected)
	flagExhaustAllowed  uint32 = 1 << 16 // Client accepts exhaust-style responses
)

// opQuery represents a parsed legacy OP_QUERY message.
// Clients using older wire protocol versions send OP_QUERY for the initial handshake.
type opQuery struct {
	Header     wireHeader
	Flags      int32
	Collection string // fullCollectionName, e.g. "admin.$cmd"
	Skip       int32
	Return     int32
	Query      bson.Raw
}

type wireHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

type documentSequence struct {
	Identifier string
	Documents  []bson.Raw
}

type opMsg struct {
	Header            wireHeader
	FlagBits          uint32
	Body              bson.Raw           // Kind 0 body document
	DocumentSequences []documentSequence // Kind 1 sections
}

var globalRequestID atomic.Int32

func init() {
	globalRequestID.Store(1000)
}

func nextRequestID() int32 {
	return globalRequestID.Add(1)
}

// readWireMessage reads a complete MongoDB wire protocol message.
func readWireMessage(r io.Reader) (*wireHeader, []byte, error) {
	var headerBuf [headerLength]byte
	if _, err := io.ReadFull(r, headerBuf[:]); err != nil {
		return nil, nil, err
	}

	hdr := wireHeader{
		MessageLength: int32(binary.LittleEndian.Uint32(headerBuf[0:4])),
		RequestID:     int32(binary.LittleEndian.Uint32(headerBuf[4:8])),
		ResponseTo:    int32(binary.LittleEndian.Uint32(headerBuf[8:12])),
		OpCode:        int32(binary.LittleEndian.Uint32(headerBuf[12:16])),
	}

	if hdr.MessageLength < headerLength || hdr.MessageLength > int32(maxMessageSize) {
		return nil, nil, fmt.Errorf("invalid message length: %d", hdr.MessageLength)
	}

	raw := make([]byte, hdr.MessageLength)
	copy(raw, headerBuf[:])
	if _, err := io.ReadFull(r, raw[headerLength:]); err != nil {
		return nil, nil, fmt.Errorf("failed to read message body: %w", err)
	}

	return &hdr, raw, nil
}

// parseOpMsg extracts the BSON body and document sequences from an OP_MSG.
func parseOpMsg(hdr *wireHeader, raw []byte) (*opMsg, error) {
	if hdr.OpCode != opMsgOpCode {
		return nil, fmt.Errorf("unsupported opcode %d, only OP_MSG (%d) is supported", hdr.OpCode, opMsgOpCode)
	}

	data := raw[headerLength:]
	if len(data) < 5 {
		return nil, fmt.Errorf("OP_MSG too short: %d bytes", len(data))
	}

	msg := &opMsg{Header: *hdr}
	msg.FlagBits = binary.LittleEndian.Uint32(data[0:4])
	pos := 4

	hasChecksum := msg.FlagBits&flagChecksumPresent != 0
	endPos := len(data)
	if hasChecksum {
		endPos -= 4
	}

	for pos < endPos {
		kind := data[pos]
		pos++

		switch kind {
		case 0: // Kind 0: single BSON document (the command body)
			if pos+4 > endPos {
				return nil, fmt.Errorf("truncated Kind 0 section")
			}
			docLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			if docLen < 5 || pos+docLen > endPos {
				return nil, fmt.Errorf("invalid Kind 0 document length: %d", docLen)
			}
			msg.Body = bson.Raw(data[pos : pos+docLen])
			pos += docLen

		case 1: // Kind 1: document sequence (e.g. insert documents, update specs)
			if pos+4 > endPos {
				return nil, fmt.Errorf("truncated Kind 1 section header")
			}
			sectionLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
			if sectionLen < 4 || pos+sectionLen > endPos {
				return nil, fmt.Errorf("invalid Kind 1 section length: %d", sectionLen)
			}
			sectionEnd := pos + sectionLen
			innerPos := pos + 4 // skip the length field

			// Read C-string identifier (field name, e.g. "documents", "updates")
			identEnd := innerPos
			for identEnd < sectionEnd && data[identEnd] != 0 {
				identEnd++
			}
			if identEnd >= sectionEnd {
				return nil, fmt.Errorf("unterminated identifier in Kind 1 section")
			}
			identifier := string(data[innerPos:identEnd])
			innerPos = identEnd + 1

			// Read BSON documents
			var docs []bson.Raw
			for innerPos < sectionEnd {
				if innerPos+4 > sectionEnd {
					break
				}
				docLen := int(binary.LittleEndian.Uint32(data[innerPos : innerPos+4]))
				if docLen < 5 || innerPos+docLen > sectionEnd {
					return nil, fmt.Errorf("invalid document in Kind 1 section")
				}
				docs = append(docs, bson.Raw(data[innerPos:innerPos+docLen]))
				innerPos += docLen
			}

			msg.DocumentSequences = append(msg.DocumentSequences, documentSequence{
				Identifier: identifier,
				Documents:  docs,
			})
			pos = sectionEnd

		default:
			return nil, fmt.Errorf("unknown section kind: %d", kind)
		}
	}

	if msg.Body == nil {
		return nil, fmt.Errorf("OP_MSG missing Kind 0 body section")
	}

	return msg, nil
}

// parseOpQuery extracts the query document from a legacy OP_QUERY message.
func parseOpQuery(hdr *wireHeader, raw []byte) (*opQuery, error) {
	data := raw[headerLength:]
	// Minimum: 4 (flags) + 1 (empty cstring) + 4 (skip) + 4 (return) + 5 (minimal BSON) = 18
	if len(data) < 18 {
		return nil, fmt.Errorf("OP_QUERY too short: %d bytes", len(data))
	}

	flags := int32(binary.LittleEndian.Uint32(data[0:4]))
	pos := 4

	// Read null-terminated collection name
	nullIdx := pos
	for nullIdx < len(data) && data[nullIdx] != 0 {
		nullIdx++
	}
	if nullIdx >= len(data) {
		return nil, fmt.Errorf("unterminated collection name in OP_QUERY")
	}
	collection := string(data[pos:nullIdx])
	pos = nullIdx + 1

	if pos+8 > len(data) {
		return nil, fmt.Errorf("truncated OP_QUERY after collection name")
	}
	skip := int32(binary.LittleEndian.Uint32(data[pos : pos+4]))
	ret := int32(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
	pos += 8

	if pos+4 > len(data) {
		return nil, fmt.Errorf("truncated OP_QUERY: no query document")
	}
	docLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	if docLen < 5 || pos+docLen > len(data) {
		return nil, fmt.Errorf("invalid query document length: %d", docLen)
	}
	query := bson.Raw(data[pos : pos+docLen])

	return &opQuery{
		Header:     *hdr,
		Flags:      flags,
		Collection: collection,
		Skip:       skip,
		Return:     ret,
		Query:      query,
	}, nil
}

// buildOpMsg wraps a BSON document in an OP_MSG response.
func buildOpMsg(responseTo int32, doc bson.Raw) []byte {
	totalLen := headerLength + 4 + 1 + len(doc) // header + flagBits + kind byte + doc
	msg := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[4:8], uint32(nextRequestID()))
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgOpCode))
	binary.LittleEndian.PutUint32(msg[16:20], 0) // flagBits = 0
	msg[20] = 0                                  // Kind 0
	copy(msg[21:], doc)

	return msg
}

func writeWireMessage(w io.Writer, msg []byte) error {
	_, err := w.Write(msg)
	return err
}

// getCommandName returns the first key in the BSON document (the command name).
func getCommandName(doc bson.Raw) string {
	elems, err := doc.Elements()
	if err != nil || len(elems) == 0 {
		return ""
	}
	return elems[0].Key()
}

// getStringField returns a string field from a BSON document, or "" if absent.
func getStringField(doc bson.Raw, key string) string {
	val, err := doc.LookupErr(key)
	if err != nil {
		return ""
	}
	str, ok := val.StringValueOK()
	if !ok {
		return ""
	}
	return str
}

// stripFields removes the specified top-level fields from a BSON document.
func stripFields(doc bson.Raw, fields ...string) (bson.Raw, error) {
	remove := make(map[string]bool, len(fields))
	for _, f := range fields {
		remove[f] = true
	}

	var d bson.D
	if err := bson.Unmarshal(doc, &d); err != nil {
		return nil, err
	}

	result := make(bson.D, 0, len(d))
	for _, elem := range d {
		if !remove[elem.Key] {
			result = append(result, elem)
		}
	}

	return bson.Marshal(result)
}

// mergeDocumentSequences folds Kind 1 document sequences into the command body
// so it can be passed to RunCommand as a single document.
// For example, an insert's Kind 1 "documents" sequence becomes the "documents" array field.
func mergeDocumentSequences(body bson.Raw, sequences []documentSequence) (bson.Raw, error) {
	if len(sequences) == 0 {
		return body, nil
	}

	var doc bson.D
	if err := bson.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal body for merge: %w", err)
	}

	for _, seq := range sequences {
		arr := make(bson.A, 0, len(seq.Documents))
		for _, raw := range seq.Documents {
			var subdoc bson.D
			if err := bson.Unmarshal(raw, &subdoc); err != nil {
				return nil, fmt.Errorf("failed to unmarshal document in sequence %q: %w", seq.Identifier, err)
			}
			arr = append(arr, subdoc)
		}
		doc = append(doc, bson.E{Key: seq.Identifier, Value: arr})
	}

	return bson.Marshal(doc)
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
