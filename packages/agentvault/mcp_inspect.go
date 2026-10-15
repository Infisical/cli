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
	// The ring holds thousands of records per session, so one record must stay small. A longer batch is
	// still read and validated in full, but only its first calls are kept and the record says so.
	maxMCPCallsPerRecord = 32

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

func (s *resolvedService) serviceType() string {
	if s.kind == serviceKindMCP {
		return serviceKindMCP
	}
	return serviceKindHTTP
}

func unparsedMCP() *mcpDetail {
	return &mcpDetail{Calls: []mcpCall{}}
}

// A body already read into memory, so applyBodySubstitutions takes the bytes rather than reading them again.
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
	if !strings.EqualFold(req.Method, http.MethodPost) {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil
	}
	if req.Header.Get("Content-Encoding") != "" || req.ContentLength > maxMCPInspectBody {
		return unparsedMCP()
	}
	if req.Body == nil || req.Body == http.NoBody {
		return parseMCPBody(nil)
	}

	original := req.Body
	body, err := io.ReadAll(io.LimitReader(original, maxMCPInspectBody+1))
	if err != nil {
		// Put back as it failed, so whatever reads the body next meets the same error and a truncated body
		// is refused or fails exactly as it would have without the inspection.
		req.Body = rechainedBody{Reader: io.MultiReader(bytes.NewReader(body), erroringReader{err}), Closer: original}
		return unparsedMCP()
	}
	if len(body) > maxMCPInspectBody {
		req.Body = rechainedBody{Reader: io.MultiReader(bytes.NewReader(body), original), Closer: original}
		return unparsedMCP()
	}
	_ = original.Close()
	if len(body) == 0 {
		req.Body = http.NoBody
	} else {
		req.Body = &bufferedBody{Reader: bytes.NewReader(body), data: body}
	}
	return parseMCPBody(body)
}

func parseMCPBody(body []byte) *mcpDetail {
	calls, truncated, ok := parseJSONRPCCalls(body)
	if !ok {
		return unparsedMCP()
	}
	return &mcpDetail{Calls: calls, Parsed: true, Truncated: truncated}
}

var errJSONRPCUnreadable = errors.New("not a JSON-RPC message the log can name")

// Returns the calls to log, whether the batch held more than were kept, and whether the body was readable.
func parseJSONRPCCalls(body []byte) ([]mcpCall, bool, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	// Numbers are only skipped, and as float64 one past its range would fail an otherwise valid body.
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, false, false
	}
	calls := []mcpCall{}
	truncated := false
	switch tok {
	case json.Delim('{'):
		call, ok, err := readJSONRPCMessage(dec)
		if err != nil {
			return nil, false, false
		}
		if ok {
			calls = append(calls, call)
		}
	case json.Delim('['):
		for dec.More() {
			elem, err := dec.Token()
			if err != nil {
				return nil, false, false
			}
			if elem != json.Delim('{') {
				if err := skipJSONValue(dec, elem); err != nil {
					return nil, false, false
				}
				continue
			}
			call, ok, err := readJSONRPCMessage(dec)
			if err != nil {
				return nil, false, false
			}
			if !ok {
				continue
			}
			if len(calls) == maxMCPCallsPerRecord {
				truncated = true
			} else {
				calls = append(calls, call)
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, false, false
		}
	default:
		return nil, false, false
	}

	// A server parsing the whole body rejects trailing content, so a second message hidden after the first
	// must not leave the log naming only the first.
	if _, err := dec.Token(); err != io.EOF {
		return nil, false, false
	}
	return calls, truncated, true
}

// Called with the opening brace consumed. A key repeated, or written in another case, makes the message
// unreadable: servers disagree on which copy wins, and Go's own decoder matches field names ignoring case,
// so the logged name could otherwise differ from the one the server runs.
func readJSONRPCMessage(dec *json.Decoder) (mcpCall, bool, error) {
	var method, tool string
	var hasMethod, hasParams, hasTool, toolNotString bool

	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return mcpCall{}, false, err
		}
		switch {
		case strings.EqualFold(key, "method"):
			if key != "method" || hasMethod {
				return mcpCall{}, false, errJSONRPCUnreadable
			}
			hasMethod = true
			if method, err = stringValue(dec); err != nil {
				return mcpCall{}, false, err
			}
		case strings.EqualFold(key, "params"):
			if key != "params" || hasParams {
				return mcpCall{}, false, errJSONRPCUnreadable
			}
			hasParams = true
			if tool, hasTool, toolNotString, err = readParamsName(dec); err != nil {
				return mcpCall{}, false, err
			}
		default:
			if err := skipNextJSONValue(dec); err != nil {
				return mcpCall{}, false, err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return mcpCall{}, false, err
	}

	if !hasMethod {
		return mcpCall{}, false, nil
	}
	if !mcpNamePattern.MatchString(method) {
		return mcpCall{}, false, errJSONRPCUnreadable
	}
	call := mcpCall{Method: method}
	if method == mcpMethodToolsCall && hasTool {
		if toolNotString || !mcpNamePattern.MatchString(tool) {
			return mcpCall{}, false, errJSONRPCUnreadable
		}
		call.Tool = tool
	}
	return call, true, nil
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
		key, err := objectKey(dec)
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

func objectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", errJSONRPCUnreadable
	}
	return key, nil
}

func stringValue(dec *json.Decoder) (string, error) {
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
