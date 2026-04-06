package mongodb

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/wiremessage"
)

const (
	opQueryOpCode int32 = 2004
	opMsgOpCode    int32  = 2013
	headerLength          = 16
	maxMessageSize        = 48 * 1024 * 1024 // 48MB

	// OP_MSG flag bits
	flagMoreToCome uint32 = 1 << 1 // Sender will send more messages (no response expected)
)

// opQuery represents a parsed legacy OP_QUERY message.
// mongosh still sends OP_QUERY for the initial isMaster/hello handshake.
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

	length, reqID, resTo, opcode, _, ok := wiremessage.ReadHeader(headerBuf[:])
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse wire message header")
	}

	hdr := wireHeader{
		MessageLength: length,
		RequestID:     reqID,
		ResponseTo:    resTo,
		OpCode:        int32(opcode),
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

// parseOpMsg extracts the BSON body and document sequences from an OP_MSG
// using the driver's wiremessage package.
func parseOpMsg(hdr *wireHeader, raw []byte) (*opMsg, error) {
	if hdr.OpCode != opMsgOpCode {
		return nil, fmt.Errorf("unsupported opcode %d, only OP_MSG (%d) is supported", hdr.OpCode, opMsgOpCode)
	}

	rem := raw[headerLength:]
	if len(rem) < 5 {
		return nil, fmt.Errorf("OP_MSG too short: %d bytes", len(rem))
	}

	msg := &opMsg{Header: *hdr}

	flags, rem, ok := wiremessage.ReadMsgFlags(rem)
	if !ok {
		return nil, fmt.Errorf("failed to read OP_MSG flags")
	}
	msg.FlagBits = uint32(flags)

	// If checksum is present, exclude the last 4 bytes from section parsing
	hasChecksum := flags&wiremessage.ChecksumPresent != 0
	sectionData := rem
	if hasChecksum && len(sectionData) >= 4 {
		sectionData = sectionData[:len(sectionData)-4]
	}

	for len(sectionData) > 0 {
		stype, afterType, typeOk := wiremessage.ReadMsgSectionType(sectionData)
		if !typeOk {
			return nil, fmt.Errorf("failed to read section type")
		}

		switch stype {
		case wiremessage.SingleDocument:
			doc, afterDoc, docOk := wiremessage.ReadMsgSectionSingleDocument(afterType)
			if !docOk {
				return nil, fmt.Errorf("failed to read Kind 0 document")
			}
			msg.Body = bson.Raw(doc)
			sectionData = afterDoc

		case wiremessage.DocumentSequence:
			identifier, docs, afterSeq, seqOk := wiremessage.ReadMsgSectionDocumentSequence(afterType)
			if !seqOk {
				return nil, fmt.Errorf("failed to read Kind 1 document sequence")
			}
			rawDocs := make([]bson.Raw, len(docs))
			for i, d := range docs {
				rawDocs[i] = bson.Raw(d)
			}
			msg.DocumentSequences = append(msg.DocumentSequences, documentSequence{
				Identifier: identifier,
				Documents:  rawDocs,
			})
			sectionData = afterSeq

		default:
			return nil, fmt.Errorf("unknown section kind: %d", stype)
		}
	}

	if msg.Body == nil {
		return nil, fmt.Errorf("OP_MSG missing Kind 0 body section")
	}

	return msg, nil
}

// parseOpQuery extracts the query document from a legacy OP_QUERY message.
// The ReadQuery* functions are deprecated in the driver ("use OpMsg instead"),
// but we must still parse OP_QUERY because mongosh and older clients send it for the initial handshake.
func parseOpQuery(hdr *wireHeader, raw []byte) (*opQuery, error) {
	rem := raw[headerLength:]

	flags, rem, ok := wiremessage.ReadQueryFlags(rem)
	if !ok {
		return nil, fmt.Errorf("failed to read OP_QUERY flags")
	}

	collection, rem, ok := wiremessage.ReadQueryFullCollectionName(rem)
	if !ok {
		return nil, fmt.Errorf("failed to read OP_QUERY collection name")
	}

	skip, rem, ok := wiremessage.ReadQueryNumberToSkip(rem)
	if !ok {
		return nil, fmt.Errorf("failed to read OP_QUERY numberToSkip")
	}

	ret, rem, ok := wiremessage.ReadQueryNumberToReturn(rem)
	if !ok {
		return nil, fmt.Errorf("failed to read OP_QUERY numberToReturn")
	}

	query, _, ok := wiremessage.ReadQueryQuery(rem)
	if !ok {
		return nil, fmt.Errorf("failed to read OP_QUERY query document")
	}

	return &opQuery{
		Header:     *hdr,
		Flags:      int32(flags),
		Collection: collection,
		Skip:       skip,
		Return:     ret,
		Query:      bson.Raw(query),
	}, nil
}

// buildOpMsgReply wraps a BSON document in an OP_MSG response.
func buildOpMsgReply(responseTo int32, doc bson.Raw) []byte {
	totalLen := headerLength + 4 + 1 + len(doc) // header + flagBits + kind byte + doc
	msg := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[4:8], uint32(nextRequestID()))
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsgOpCode))
	binary.LittleEndian.PutUint32(msg[16:20], 0) // flagBits = 0
	msg[20] = 0                                   // Kind 0
	copy(msg[21:], doc)

	return msg
}

func writeWireMessage(w io.Writer, msg []byte) error {
	_, err := w.Write(msg)
	return err
}

// getCommandName returns the first key in the BSON document (the command name).
func getCommandName(doc bson.Raw) string {
	elem, err := doc.IndexErr(0)
	if err != nil {
		return ""
	}
	return elem.Key()
}

// getStringField returns a string field from a BSON document.
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
