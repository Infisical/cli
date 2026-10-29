package agentvault

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

const (
	jsonrpcInvalidRequest = -32600
	jsonrpcInvalidParams  = -32602

	// Per message for a JSON response and per event for a stream. Anything larger is passed through as it
	// came, since a call to a hidden tool is still refused on the way in.
	maxToolsListRewrite = maxMCPInspectBody
	// What the proxy holds in memory to check one request against an allowlist. Larger than the log's cap so
	// a call with a sizeable argument still goes through, and finite so no agent can exhaust the proxy.
	maxToolsAllowlistBody = 32 << 20
)

// A request the service's tool allowlist refuses, answered by the proxy so the upstream never sees it.
type mcpToolRefusal struct {
	status int
	body   []byte
	reason string
}

func (r *mcpToolRefusal) Error() string { return r.reason }

func (r *mcpToolRefusal) write(w http.ResponseWriter) {
	if len(r.body) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(r.body)))
	}
	w.WriteHeader(r.status)
	_, _ = w.Write(r.body)
}

type jsonrpcErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   jsonrpcError    `json:"error"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Every POST to a service with an allowlist is read here, up to maxToolsAllowlistBody, whether or not session
// logs are on, and refused whole when any call in it names a tool the list leaves out. A server may parse JSON
// whatever its Content-Type, so a body that could be read as JSON is checked whatever its type, and refused
// when it does not parse strictly; any other body, such as a form-encoded OAuth token request, cannot be a
// JSON-RPC message and is forwarded. A body the proxy cannot read is refused, so the list fails closed. The
// detail is what the session log records, from the same parse.
func checkToolAllowlist(svc *resolvedService, req *http.Request, logging bool) (*mcpDetail, *mcpToolRefusal) {
	if !strings.EqualFold(req.Method, http.MethodPost) {
		// JSON-RPC only comes as a POST, but a server that ignores the method would run a body sent with any
		// other, so one that carries a body is refused rather than let past unchecked.
		if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
			return nil, nil
		}
		return nil, unreadableToolsRequest(svc.name)
	}
	mediaType, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	declaredJSON := mediaType == "application/json"
	var detail *mcpDetail
	if logging && declaredJSON {
		detail = unparsedMCP()
	}
	if req.Header.Get("Content-Encoding") != "" {
		return detail, unreadableToolsRequest(svc.name)
	}
	body, whole := bufferRequestBody(req, maxToolsAllowlistBody)
	if !whole {
		// Over the cap, or the read failed, in which case the agent has gone and never sees this answer.
		return detail, oversizedToolsRequest(svc.name)
	}
	if !declaredJSON && !mayBeJSON(body) {
		return nil, nil
	}
	if logging {
		detail = unparsedMCP()
	}
	messages, ok := parseJSONRPCMessages(body)
	if !ok {
		return detail, unreadableToolsRequest(svc.name)
	}
	if logging {
		detail = mcpDetailOf(messages)
	}

	refused := ""
	for _, message := range messages {
		if message.Method != mcpMethodToolsCall {
			continue
		}
		// A call naming no tool cannot be checked, and the server would refuse it anyway.
		if message.Tool == "" {
			return detail, unreadableToolsRequest(svc.name)
		}
		if refused == "" && !svc.allowedTools[message.Tool] {
			refused = message.Tool
		}
	}
	if refused == "" {
		return detail, nil
	}
	batch := bytes.HasPrefix(bytes.TrimSpace(body), []byte("["))
	return detail, unlistedToolRefusal(svc, refused, messages, batch, streamableHTTPClient(req))
}

// The allowlist judged the body the agent sent, and a body substitution can change the tool it names, so the
// body that goes upstream is judged again. The substitution has already put it in memory.
func toolsAllowedAfterSubstitution(svc *resolvedService, req *http.Request) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return true
	}
	body, err := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	messages, ok := parseJSONRPCMessages(body)
	if !ok {
		return false
	}
	for _, message := range messages {
		if message.Method == mcpMethodToolsCall && !svc.allowedTools[message.Tool] {
			return false
		}
	}
	return true
}

// Whether a parser could read the body as a JSON object or array, the only shapes a JSON-RPC message takes:
// its first byte after whitespace, and after a byte order mark some parsers skip, opens one. A body in UTF-16
// or UTF-32 counts too, since parsers such as Python's json.loads detect those from a byte order mark or from
// a NUL in the first four bytes; no MCP client sends one, so it fails the strict parse and is refused.
func mayBeJSON(body []byte) bool {
	if bytes.HasPrefix(body, []byte("\xfe\xff")) || bytes.HasPrefix(body, []byte("\xff\xfe")) ||
		bytes.IndexByte(body[:min(len(body), 4)], 0) >= 0 {
		return true
	}
	body = bytes.TrimLeft(bytes.TrimPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("\xef\xbb\xbf")), " \t\r\n")
	return len(body) > 0 && (body[0] == '{' || body[0] == '[')
}

func unlistedToolMessage(tool, service string) string {
	return fmt.Sprintf("Tool %q isn't allowed on service %q. An admin controls which tools this service allows in Agent Vault.", tool, service)
}

// The legacy SSE transport's clients ignore the body of a successful POST, since its answer is meant to
// arrive on the event stream, so a refusal sent as 200 would leave the call waiting until it timed out.
// They surface a failed POST as an error instead, so they get 403 with the same body. A Streamable HTTP
// client is told apart by its Accept header, which the specification requires to list both types and the
// SSE clients leave at the default.
func unlistedToolRefusal(svc *resolvedService, tool string, messages []jsonrpcMessage, batch, streamable bool) *mcpToolRefusal {
	reason := unlistedToolMessage(tool, svc.name)
	responses := make([]jsonrpcErrorResponse, 0, len(messages))
	// Without the refused tool's name, so a long name in a long batch is not copied into every answer.
	batchRefused := fmt.Sprintf("This batch was refused because it calls a tool that isn't allowed on service %q. An admin controls which tools this service allows in Agent Vault.", svc.name)
	for _, message := range messages {
		if message.id == nil {
			continue
		}
		msg := batchRefused
		if message.Method == mcpMethodToolsCall && !svc.allowedTools[message.Tool] {
			msg = unlistedToolMessage(message.Tool, svc.name)
		}
		responses = append(responses, newJSONRPCError(message.id, jsonrpcInvalidParams, msg))
	}

	refusal := &mcpToolRefusal{status: http.StatusOK, reason: reason}
	switch {
	case len(responses) == 0 && streamable:
		// Only notifications, which get no answer. 202 is what the server would have said.
		refusal.status = http.StatusAccepted
		return refusal
	case len(responses) == 0:
		refusal.body = marshalJSONRPC(newJSONRPCError(nil, jsonrpcInvalidParams, reason))
	case batch:
		refusal.body = marshalJSONRPC(responses)
	default:
		refusal.body = marshalJSONRPC(responses[0])
	}
	if !streamable {
		refusal.status = http.StatusForbidden
	}
	return refusal
}

// With no id to answer, a JSON-RPC error alone would match no pending call, so the status carries the
// failure for any client.
func unreadableToolsRequest(service string) *mcpToolRefusal {
	return toolsRequestRefusal(http.StatusBadRequest, fmt.Sprintf("Agent Vault couldn't read this request to check which tools it calls, so it was refused. Service %q only allows some tools, so requests to it that carry a body must be uncompressed POSTs, and a JSON body must be valid JSON-RPC.", service))
}

func oversizedToolsRequest(service string) *mcpToolRefusal {
	return toolsRequestRefusal(http.StatusRequestEntityTooLarge, fmt.Sprintf("Agent Vault refused this request because its body is larger than the %d MiB it can check against the tools service %q allows.", maxToolsAllowlistBody>>20, service))
}

func toolsRequestRefusal(status int, reason string) *mcpToolRefusal {
	return &mcpToolRefusal{
		status: status,
		body:   marshalJSONRPC(newJSONRPCError(nil, jsonrpcInvalidRequest, reason)),
		reason: reason,
	}
}

func newJSONRPCError(id json.RawMessage, code int, message string) jsonrpcErrorResponse {
	if id == nil {
		id = json.RawMessage("null")
	}
	return jsonrpcErrorResponse{JSONRPC: "2.0", ID: id, Error: jsonrpcError{Code: code, Message: message}}
}

func marshalJSONRPC(v any) []byte {
	b, _ := encodeJSON(v)
	return b
}

func streamableHTTPClient(req *http.Request) bool {
	var acceptsJSON, acceptsStream bool
	for _, value := range req.Header.Values("Accept") {
		for _, part := range strings.Split(value, ",") {
			mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			acceptsJSON = acceptsJSON || mediaType == "application/json"
			acceptsStream = acceptsStream || mediaType == "text/event-stream"
		}
	}
	return acceptsJSON && acceptsStream
}

// Removes the tools a service's allowlist leaves out from every tools/list result in the response, so the
// agent is only offered tools it can call. Matched on the result's shape rather than on the request id, so
// the legacy transport's results, which arrive on another connection, need no tracking. The proxy drops the
// agent's Accept-Encoding so Go decompresses the response first; a body compressed anyway, one over the cap,
// and anything that does not parse pass through untouched.
func hideUnlistedTools(resp *http.Response, allowed map[string]bool) {
	if resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return
	}
	switch mediaType {
	case "application/json":
		hideUnlistedToolsInJSON(resp, allowed)
	case "text/event-stream":
		resp.Body = rechainedBody{Reader: &sseToolsFilter{src: bufio.NewReader(resp.Body), allowed: allowed}, Closer: resp.Body}
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
	}
}

func hideUnlistedToolsInJSON(resp *http.Response, allowed map[string]bool) {
	original := resp.Body
	body, rest, whole := readBounded(original, maxToolsListRewrite)
	if !whole {
		resp.Body = rest
		return
	}
	if filtered, changed := filterToolsListJSON(body, allowed); changed {
		body = filtered
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		resp.ContentLength = int64(len(body))
	}
	resp.Body = rechainedBody{Reader: bytes.NewReader(body), Closer: original}
}

// Returns the message, or batch of messages, with unlisted tools removed, and whether anything was.
func filterToolsListJSON(data []byte, allowed map[string]bool) ([]byte, bool) {
	// Most responses are not a tools/list result, and this spares them a full decode. The key can only be
	// spelled another way with a \u escape, so a body holding one is decoded too.
	if !bytes.Contains(data, []byte(`"tools"`)) && !bytes.Contains(data, []byte(`\u`)) {
		return nil, false
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("[")) {
		return filterToolsListMessage(trimmed, allowed)
	}
	var batch []json.RawMessage
	if json.Unmarshal(trimmed, &batch) != nil {
		return nil, false
	}
	changed := false
	for i, message := range batch {
		if filtered, ok := filterToolsListMessage(message, allowed); ok {
			batch[i], changed = filtered, true
		}
	}
	if !changed {
		return nil, false
	}
	return encodeJSON(batch)
}

func filterToolsListMessage(data []byte, allowed map[string]bool) ([]byte, bool) {
	var message, result map[string]json.RawMessage
	var tools []json.RawMessage
	if json.Unmarshal(data, &message) != nil ||
		json.Unmarshal(message["result"], &result) != nil || result == nil ||
		json.Unmarshal(result["tools"], &tools) != nil || tools == nil {
		return nil, false
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, tool := range tools {
		var fields map[string]json.RawMessage
		var name string
		// An entry without a readable name cannot be called by one, so it is dropped rather than leaving the
		// whole list unfiltered.
		if json.Unmarshal(tool, &fields) != nil || json.Unmarshal(fields["name"], &name) != nil {
			continue
		}
		if allowed[name] {
			kept = append(kept, tool)
		}
	}
	if len(kept) == len(tools) {
		return nil, false
	}
	var ok bool
	if result["tools"], ok = encodeJSON(kept); !ok {
		return nil, false
	}
	if message["result"], ok = encodeJSON(result); !ok {
		return nil, false
	}
	return encodeJSON(message)
}

// Without HTML escaping, so the descriptions that are kept reach the agent as the server wrote them.
func encodeJSON(v any) ([]byte, bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), true
}

// Rewrites a text/event-stream one event at a time, handing each on as soon as it is complete so the
// stream keeps streaming. An event that grows past the cap is passed on as it arrives instead.
type sseToolsFilter struct {
	src     *bufio.Reader
	allowed map[string]bool
	event   []byte
	out     []byte
	// The current event outgrew the cap and is streamed through until it ends.
	passthrough bool
	// The previous read stopped part way through a line longer than the reader's buffer.
	midLine bool
	// The previous line ended in a CR that was the last byte read, so an LF read next belongs to that line.
	afterCR bool
	err     error
}

func (f *sseToolsFilter) Read(p []byte) (int, error) {
	for len(f.out) == 0 {
		if f.err != nil {
			return 0, f.err
		}
		f.fill()
	}
	n := copy(p, f.out)
	f.out = f.out[n:]
	return n, nil
}

func (f *sseToolsFilter) fill() {
	line, err := readSSELine(f.src)
	tailOfCRLF := f.afterCR && len(line) == 1 && line[0] == '\n'
	startsLine := !f.midLine && !tailOfCRLF
	endsEvent := startsLine && isBlankSSELine(line)
	f.midLine = err == bufio.ErrBufferFull
	f.afterCR = err == nil && len(line) > 0 && line[len(line)-1] == '\r'

	switch {
	case tailOfCRLF && len(f.event) == 0:
		f.out = append([]byte(nil), line...)
	case tailOfCRLF:
		f.event = append(f.event, line...)
	case f.passthrough:
		f.out = append([]byte(nil), line...)
		if endsEvent {
			f.passthrough = false
		}
	case endsEvent:
		f.out = rewriteSSEEvent(append(f.event, line...), f.allowed)
		f.event = nil
	// A comment between events, usually a keepalive, needs no rewriting and is handed on at once, so an idle
	// stream does not look dead to the agent while it waits for a blank line.
	case len(f.event) == 0 && startsLine && err == nil && bytes.HasPrefix(line, []byte(":")):
		f.out = append([]byte(nil), line...)
	default:
		f.event = append(f.event, line...)
		if len(f.event) > maxToolsListRewrite {
			f.out, f.event, f.passthrough = f.event, nil, true
		}
	}

	if err != nil && err != bufio.ErrBufferFull {
		f.out = append(f.out, f.event...)
		f.event = nil
		f.err = err
	}
}

// Reads up to the end of a line, which in SSE is an LF, a CRLF, or a bare CR. A CR at the end of what has
// arrived ends the line at once rather than waiting to see whether an LF follows, so an event is never held
// back; an LF read next comes back alone, as the tail of that line. err is bufio.ErrBufferFull when the line
// is longer than the reader's buffer. The line is only valid until the next read, as with ReadSlice.
func readSSELine(r *bufio.Reader) ([]byte, error) {
	n, scanned := 1, 0
	for {
		buf, err := r.Peek(n)
		if buffered := r.Buffered(); buffered > len(buf) {
			buf, _ = r.Peek(buffered)
		}
		if end := sseLineEnd(buf[scanned:]); end > 0 {
			_, _ = r.Discard(scanned + end)
			return buf[:scanned+end], nil
		}
		if err != nil {
			_, _ = r.Discard(len(buf))
			return buf, err
		}
		n, scanned = len(buf)+1, len(buf)
	}
}

// The length of the first line in data, line ending included, or 0 when data holds no line ending.
func sseLineEnd(data []byte) int {
	i := bytes.IndexAny(data, "\r\n")
	if i < 0 {
		return 0
	}
	if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
		return i + 2
	}
	return i + 1
}

func splitSSELines(event []byte) [][]byte {
	var lines [][]byte
	for len(event) > 0 {
		end := sseLineEnd(event)
		if end == 0 {
			end = len(event)
		}
		lines = append(lines, event[:end])
		event = event[end:]
	}
	return lines
}

func isBlankSSELine(line []byte) bool {
	return len(line) > 0 && len(bytes.TrimRight(line, "\r\n")) == 0
}

// An event whose data is a tools/list result is rebuilt with the filtered data on one data line where the
// first one was; every other line keeps its place. Any other event is returned as it came.
func rewriteSSEEvent(event []byte, allowed map[string]bool) []byte {
	lines := splitSSELines(event)
	var data [][]byte
	for _, line := range lines {
		if value, ok := sseDataValue(line); ok {
			data = append(data, value)
		}
	}
	if len(data) == 0 {
		return event
	}
	filtered, changed := filterToolsListJSON(bytes.Join(data, []byte("\n")), allowed)
	if !changed {
		return event
	}

	out := make([]byte, 0, len(event))
	wrote := false
	for _, line := range lines {
		if _, ok := sseDataValue(line); !ok {
			out = append(out, line...)
			continue
		}
		if !wrote {
			out = append(out, "data: "...)
			out = append(out, filtered...)
			out = append(out, '\n')
			wrote = true
		}
	}
	return out
}

func sseDataValue(line []byte) ([]byte, bool) {
	line = bytes.TrimRight(line, "\r\n")
	if !bytes.HasPrefix(line, []byte("data")) {
		return nil, false
	}
	rest := line[len("data"):]
	if len(rest) == 0 {
		return rest, true
	}
	if rest[0] != ':' {
		return nil, false
	}
	return bytes.TrimPrefix(rest[1:], []byte(" ")), true
}
