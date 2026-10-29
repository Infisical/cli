package agentvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
)

const (
	serviceKindHTTP = "http"
	serviceKindMCP  = "mcp"

	maxMCPInspectBody = 1 << 20
	// The ring holds thousands of records per session and is capped by count, so one record must stay small:
	// eight full-length names add about as much as the longest logged path. A longer batch is still read and
	// validated in full, but only its first calls are kept and the record says so.
	maxMCPCallsPerRecord = 8

	mcpMethodToolsCall = "tools/call"
)

var mcpNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)

type mcpCall struct {
	Method string `json:"method"`
	Tool   string `json:"tool,omitempty"`
}

type mcpDetail struct {
	Calls     []mcpCall `json:"calls"`
	Parsed    bool      `json:"parsed"`
	Truncated bool      `json:"truncated,omitempty"`
}

func unparsedMCP() *mcpDetail {
	return &mcpDetail{Calls: []mcpCall{}}
}

// A body already read into memory. It keeps the complete bytes so an OAuth retry can send the same body again.
type bufferedBody struct {
	*bytes.Reader
	data []byte
}

func (*bufferedBody) Close() error { return nil }

type rechainedBody struct {
	io.Reader
	io.Closer
}

type erroringReader struct{ err error }

func (r erroringReader) Read([]byte) (int, error) { return 0, r.err }

// Returns nil when the request is not one the proxy parses, so the record carries no mcp detail at all.
// Never refuses or alters the request: whatever is read is put back so the upstream gets the same bytes.
func inspectMCPRequest(req *http.Request) *mcpDetail {
	body, applicable, whole := bufferMCPRequest(req, maxMCPInspectBody)
	if !applicable {
		return nil
	}
	if !whole {
		return unparsedMCP()
	}
	return parseMCPBody(body)
}

// Reads a JSON-RPC POST body into memory, up to limit bytes or whole when limit is negative, so it can be
// parsed and sent again on an OAuth retry. applicable is false when the request is not one the proxy buffers,
// and whole is false when the body could not be held in full. Whatever is read is put back so the upstream
// gets the same bytes.
func bufferMCPRequest(req *http.Request, limit int64) (body []byte, applicable, whole bool) {
	if !strings.EqualFold(req.Method, http.MethodPost) {
		return nil, false, false
	}
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, false, false
	}
	if req.Header.Get("Content-Encoding") != "" || (limit >= 0 && req.ContentLength > limit) {
		return nil, true, false
	}
	if req.Body == nil || req.Body == http.NoBody {
		return nil, true, true
	}

	original := req.Body
	var rest io.ReadCloser
	if body, rest, whole = readBounded(original, limit); !whole {
		req.Body = rest
		return nil, true, false
	}
	_ = original.Close()
	if len(body) == 0 {
		req.Body = http.NoBody
	} else {
		req.Body = &bufferedBody{Reader: bytes.NewReader(body), data: body}
	}
	return body, true, true
}

// Reads rc whole, or up to limit bytes when limit is not negative. When it cannot, whole is false and rest
// gives back what was read followed by the rest of rc, or by the error the read failed with, so whatever
// reads it next meets the same bytes and a truncated body is refused or fails exactly as it would have
// without this read.
func readBounded(rc io.ReadCloser, limit int64) (body []byte, rest io.ReadCloser, whole bool) {
	var r io.Reader = rc
	if limit >= 0 {
		r = io.LimitReader(rc, limit+1)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, rechainedBody{Reader: io.MultiReader(bytes.NewReader(body), erroringReader{err}), Closer: rc}, false
	}
	if limit >= 0 && int64(len(body)) > limit {
		return nil, rechainedBody{Reader: io.MultiReader(bytes.NewReader(body), rc), Closer: rc}, false
	}
	return body, nil, true
}

func parseMCPBody(body []byte) *mcpDetail {
	messages, ok := parseJSONRPCMessages(body)
	if !ok {
		return unparsedMCP()
	}
	return mcpDetailOf(messages)
}

var errJSONRPCUnreadable = errors.New("not a JSON-RPC message the proxy can read")

type jsonrpcMessage struct {
	mcpCall
	// The request's id as it was sent, or nil when the message carries none.
	id json.RawMessage
}

// The first calls of a parsed body, as the log records them. mcpNamePattern is applied here and only here:
// a name outside it leaves the record unparsed, while a tool allowlist compares names exactly however they
// are spelled.
func mcpDetailOf(messages []jsonrpcMessage) *mcpDetail {
	calls := make([]mcpCall, 0, min(len(messages), maxMCPCallsPerRecord))
	truncated := false
	for _, message := range messages {
		if !mcpNamePattern.MatchString(message.Method) || (message.Tool != "" && !mcpNamePattern.MatchString(message.Tool)) {
			return unparsedMCP()
		}
		if len(calls) == maxMCPCallsPerRecord {
			truncated = true
			continue
		}
		calls = append(calls, message.mcpCall)
	}
	return &mcpDetail{Calls: calls, Parsed: true, Truncated: truncated}
}

// Every message that names a method, however long the batch, and whether the body was readable.
func parseJSONRPCMessages(body []byte) ([]jsonrpcMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	// Numbers are only skipped, and as float64 one past its range would fail an otherwise valid body.
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	messages := []jsonrpcMessage{}
	switch tok {
	case json.Delim('{'):
		message, ok, err := readJSONRPCMessage(dec)
		if err != nil {
			return nil, false
		}
		if ok {
			messages = append(messages, message)
		}
	case json.Delim('['):
		for dec.More() {
			elem, err := dec.Token()
			if err != nil {
				return nil, false
			}
			if elem != json.Delim('{') {
				if err := skipJSONValue(dec, elem); err != nil {
					return nil, false
				}
				continue
			}
			message, ok, err := readJSONRPCMessage(dec)
			if err != nil {
				return nil, false
			}
			if ok {
				messages = append(messages, message)
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, false
		}
	default:
		return nil, false
	}

	// A server parsing the whole body rejects trailing content, so a second message hidden after the first
	// must not leave the log naming only the first.
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return messages, true
}

// Called with the opening brace consumed. A key repeated, or written in another case, makes the message
// unreadable: servers disagree on which copy wins, and Go's own decoder matches field names ignoring case,
// so the name logged or checked could otherwise differ from the one the server runs.
func readJSONRPCMessage(dec *json.Decoder) (jsonrpcMessage, bool, error) {
	var method, tool string
	var id json.RawMessage
	var hasMethod, hasParams, hasID, hasTool, toolNotString bool

	for dec.More() {
		key, err := readJSONString(dec)
		if err != nil {
			return jsonrpcMessage{}, false, err
		}
		switch {
		case strings.EqualFold(key, "method"):
			if key != "method" || hasMethod {
				return jsonrpcMessage{}, false, errJSONRPCUnreadable
			}
			hasMethod = true
			if method, err = readJSONString(dec); err != nil {
				return jsonrpcMessage{}, false, err
			}
		case strings.EqualFold(key, "params"):
			if key != "params" || hasParams {
				return jsonrpcMessage{}, false, errJSONRPCUnreadable
			}
			hasParams = true
			if tool, hasTool, toolNotString, err = readParamsName(dec); err != nil {
				return jsonrpcMessage{}, false, err
			}
		// Echoed back in a refusal, so it has to be the id the client will match its pending call against.
		case strings.EqualFold(key, "id"):
			if key != "id" || hasID {
				return jsonrpcMessage{}, false, errJSONRPCUnreadable
			}
			hasID = true
			if id, err = readJSONRPCID(dec); err != nil {
				return jsonrpcMessage{}, false, err
			}
		default:
			if err := skipNextJSONValue(dec); err != nil {
				return jsonrpcMessage{}, false, err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return jsonrpcMessage{}, false, err
	}

	if !hasMethod {
		return jsonrpcMessage{}, false, nil
	}
	message := jsonrpcMessage{mcpCall: mcpCall{Method: method}, id: id}
	if method == mcpMethodToolsCall && hasTool {
		if toolNotString || tool == "" {
			return jsonrpcMessage{}, false, errJSONRPCUnreadable
		}
		message.Tool = tool
	}
	return message, true, nil
}

// A string, a number or null, re-encoded from its token. Anything else is not a valid id and reads as null,
// which is what a JSON-RPC server answers an invalid request with.
func readJSONRPCID(dec *json.Decoder) (json.RawMessage, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok.(type) {
	case string, json.Number, nil:
		return json.Marshal(tok)
	}
	if err := skipJSONValue(dec, tok); err != nil {
		return nil, err
	}
	return json.RawMessage("null"), nil
}

// Only name is kept. Every other member, arguments included, is stepped over without being stored. A name
// that is not a string is reported rather than refused here, since it only matters when the method is
// tools/call.
func readParamsName(dec *json.Decoder) (name string, hasName, nameNotString bool, err error) {
	tok, err := dec.Token()
	if err != nil {
		return "", false, false, err
	}
	if tok != json.Delim('{') {
		return "", false, false, skipJSONValue(dec, tok)
	}

	for dec.More() {
		key, err := readJSONString(dec)
		if err != nil {
			return "", false, false, err
		}
		if !strings.EqualFold(key, "name") {
			if err := skipNextJSONValue(dec); err != nil {
				return "", false, false, err
			}
			continue
		}
		if key != "name" || hasName {
			return "", false, false, errJSONRPCUnreadable
		}
		hasName = true
		value, err := dec.Token()
		if err != nil {
			return "", false, false, err
		}
		if str, ok := value.(string); ok {
			name = str
		} else {
			nameNotString = true
			if err := skipJSONValue(dec, value); err != nil {
				return "", false, false, err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return "", false, false, err
	}
	return name, hasName, nameNotString, nil
}

func readJSONString(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	s, ok := tok.(string)
	if !ok {
		return "", errJSONRPCUnreadable
	}
	return s, nil
}

func skipNextJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	return skipJSONValue(dec, tok)
}

// Called with the value's first token already read; consumes the rest of it when it is an object or array.
func skipJSONValue(dec *json.Decoder, first json.Token) error {
	if first != json.Delim('{') && first != json.Delim('[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}
