package agentvault

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	jsonrpcInvalidRequest = -32600
	jsonrpcInvalidParams  = -32602
	// Outside the range JSON-RPC and MCP reserve, which MCP asks of codes it doesn't define.
	jsonrpcHookRefused = -31000

	// Per message for a JSON response and per event for a stream. Anything larger is passed through as it
	// came, since a call to a hidden tool is still refused on the way in.
	maxToolsListRewrite = maxMCPInspectBody
	// What the proxy holds in memory to check one request against an allowlist. Larger than the log's cap so
	// a call with a sizeable argument still goes through, and finite so no agent can exhaust the proxy.
	maxToolsAllowlistBody = 32 << 20
	// A refusal names the tool it refused, cut to the longest name an admin could have allowed, so an agent
	// can't make the answer and the warning logged with it as large as its request.
	maxRefusedToolName = 128

	mcpMethodHeader = "Mcp-Method"
	mcpNameHeader   = "Mcp-Name"
)

// A request the service's tool allowlist or hook refuses, answered by the proxy so the upstream never sees it.
type mcpToolRefusal struct {
	status int
	body   []byte
	reason string
	// Empty for the allowlist's own refusals, which are blocked and carry no code.
	decision string
	code     string
	// For a legacy SSE client: the refusal can be sent on the event stream the server opened for this POST,
	// as the server's own answer would be. streamEvent is what goes on it, nil when there is nothing to
	// answer.
	overStream  bool
	streamEvent []byte
}

func (r *mcpToolRefusal) Error() string { return r.reason }

func (r *mcpToolRefusal) write(w http.ResponseWriter) {
	if r.code != "" {
		w.Header().Set(HeaderError, r.code)
	}
	if r.code == errorCodeHookFailed {
		w.Header().Set("Retry-After", hookFailedRetryAfter)
	}
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

type jsonrpcToolErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  mcpToolResult   `json:"result"`
}

type mcpToolResult struct {
	IsError bool             `json:"isError"`
	Content []mcpTextContent `json:"content"`
}

type mcpTextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Every POST to a service with an allowlist is read here, up to maxToolsAllowlistBody, whether or not session
// logs are on, and refused whole when any call in it names a tool the list leaves out. A server may parse JSON
// whatever its Content-Type, so a body that could be read as JSON is checked whatever its type, and refused
// when it does not parse strictly; any other body, such as a form-encoded OAuth token request, cannot be a
// JSON-RPC message and is forwarded. A body the proxy cannot read is refused, so the list fails closed: one
// compressed, declared in a charset other than UTF-8, or whose routing headers differ from it. The
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
	mediaType, readableAsUTF8 := requestMediaType(req.Header)
	declaredJSON := mediaType == "application/json"
	var detail *mcpDetail
	if logging && declaredJSON {
		detail = unparsedMCP()
	}
	if req.Header.Get("Content-Encoding") != "" || !readableAsUTF8 {
		return detail, unreadableToolsRequest(svc.name)
	}
	body, whole := bufferRequestBody(req, maxToolsAllowlistBody)
	if !whole {
		// Over the cap, or the read failed, in which case the agent has gone and never sees this answer.
		return detail, oversizedToolsRequest(svc.name)
	}
	routingHeaders := len(req.Header.Values(mcpMethodHeader)) > 0 || len(req.Header.Values(mcpNameHeader)) > 0
	if !declaredJSON && !mayBeJSON(body) {
		// A gateway may route on the headers alone, so they need a body they can be checked against.
		if routingHeaders {
			return nil, unreadableToolsRequest(svc.name)
		}
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
	batch := bytes.HasPrefix(bytes.TrimSpace(body), []byte("["))
	if routingHeaders && !routingHeadersMatch(req.Header, messages, batch) {
		return detail, unreadableToolsRequest(svc.name)
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
	return detail, unlistedToolRefusal(svc, refused, messages, batch, streamableHTTPClient(req))
}

// The body's media type, and whether a server would decode it as UTF-8, the only encoding the proxy reads.
// Servers such as express.json() decode the body with the declared charset before parsing, so in UTF-7 a
// string the proxy reads as one tool name can hold a second "name" key the server sees and runs. A header
// that doesn't parse, such as one naming charset twice (Go fails, Node keeps the last), can't be trusted
// either, and neither can two Content-Type headers. us-ascii is refused as well: Node clears each byte's
// high bit when decoding it, which turns 0xA2 into a quote. Nor can RFC 2231 parameters such as charset*= or
// charset*0=: Go merges them into charset, over a plain charset that Node reads instead.
func requestMediaType(header http.Header) (string, bool) {
	values := header.Values("Content-Type")
	if len(values) == 0 {
		return "", true
	}
	mediaType, params, err := mime.ParseMediaType(values[0])
	if len(values) > 1 || err != nil || hasExtendedParameter(values[0]) {
		return "", false
	}
	charset, named := params["charset"]
	return mediaType, !named || strings.EqualFold(charset, "utf-8") || strings.EqualFold(charset, "utf8")
}

// Whether a parameter name in a Content-Type value has an asterisk, which marks the RFC 2231 extended form.
func hasExtendedParameter(value string) bool {
	inName, inQuote, escaped := false, false, false
	for _, c := range value {
		switch {
		case escaped:
			escaped = false
		case inQuote:
			escaped = c == '\\'
			inQuote = c != '"'
		case c == '"':
			inQuote = true
		case c == ';':
			inName = true
		case c == '=':
			inName = false
		case inName && c == '*':
			return true
		}
	}
	return false
}

// The 2026-07-28 revision of the specification lets a gateway route on Mcp-Method and Mcp-Name while the
// server runs the body, and requires a server to refuse a request whose headers differ from its body. The
// proxy refuses one too, so a server that skips that check can't be sent a tool the headers hide. The headers
// describe one message, so they never go with a batch.
func routingHeadersMatch(header http.Header, messages []jsonrpcMessage, batch bool) bool {
	methods, names := header.Values(mcpMethodHeader), header.Values(mcpNameHeader)
	if len(methods) > 1 || len(names) > 1 || batch || len(messages) != 1 {
		return false
	}
	message := messages[0]
	if len(methods) == 1 && methods[0] != message.Method {
		return false
	}
	return len(names) == 0 || message.Method != mcpMethodToolsCall || names[0] == message.Tool
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
	return fmt.Sprintf("Tool %q isn't allowed on service %q. An admin controls which tools this service allows in Agent Vault.", truncateLogged(tool, maxRefusedToolName), service)
}

// The legacy SSE transport's clients ignore the body of a successful POST, since its answer arrives on the
// event stream, and some treat a failed POST as the end of the connection: the Python SDK stops sending, so
// every later call fails too. So the refusal goes where the server's answer would, on the stream, and the
// POST gets the 202 the server would have sent (see sseStreamRegistry.deliver). Only when the proxy hasn't
// seen that stream does the client get a 403 with the same body instead. A Streamable HTTP client is told
// apart by its Accept header, which the specification requires to list both types and the SSE clients leave
// at the default.
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
		refusal.overStream = true
		if len(responses) > 0 {
			refusal.streamEvent = sseMessageEvent(refusal.body)
		}
	}
	return refusal
}

const hookBatchRefusedMessage = "This batch was refused by your organization's hook."

func hookDeniedMCPRefusal(message string, messages []jsonrpcMessage, parsed, batch, streamable bool) *mcpToolRefusal {
	return hookMCPRefusal(message, messages, parsed, batch, streamable, decisionBlocked, errorCodeHookDenied, http.StatusForbidden)
}

func hookFailedMCPRefusal(messages []jsonrpcMessage, parsed, batch, streamable bool) *mcpToolRefusal {
	return hookMCPRefusal(hookFailedRequestMessage, messages, parsed, batch, streamable, decisionError, errorCodeHookFailed, http.StatusServiceUnavailable)
}

// A tool call gets a tool result with isError set rather than a JSON-RPC error: MCP clients hand a tool's error
// result to the model, but many replace a protocol error with a generic one, and the hook's message is for the
// model to act on. Every other request gets a JSON-RPC error with the same text, and delivery follows
// unlistedToolRefusal, including on the event stream of a legacy SSE client.
func hookMCPRefusal(text string, messages []jsonrpcMessage, parsed, batch, streamable bool, decision, code string, status int) *mcpToolRefusal {
	refusal := &mcpToolRefusal{status: http.StatusOK, reason: text, decision: decision, code: code}
	if !parsed {
		refusal.status = status
		refusal.body = marshalJSONRPC(newJSONRPCError(nil, jsonrpcHookRefused, text))
		return refusal
	}
	// One answer carries the hook's text, so a long message in a long batch is not copied into every answer. It is
	// the first tool call's when there is one: clients hand a tool result to the model but may hide an error.
	carrier := -1
	for i, message := range messages {
		if message.id == nil {
			continue
		}
		if carrier == -1 || (message.Method == mcpMethodToolsCall && messages[carrier].Method != mcpMethodToolsCall) {
			carrier = i
		}
	}
	responses := make([]any, 0, len(messages))
	for i, message := range messages {
		if message.id == nil {
			continue
		}
		msg := text
		if i != carrier {
			msg = hookBatchRefusedMessage
		}
		if message.Method == mcpMethodToolsCall {
			responses = append(responses, jsonrpcToolErrorResponse{
				JSONRPC: "2.0",
				ID:      message.id,
				Result:  mcpToolResult{IsError: true, Content: []mcpTextContent{{Type: "text", Text: msg}}},
			})
			continue
		}
		responses = append(responses, newJSONRPCError(message.id, jsonrpcHookRefused, msg))
	}

	switch {
	case len(responses) == 0 && streamable:
		refusal.status = http.StatusAccepted
		return refusal
	case len(responses) == 0:
		refusal.body = marshalJSONRPC(newJSONRPCError(nil, jsonrpcHookRefused, text))
	case batch:
		refusal.body = marshalJSONRPC(responses)
	default:
		refusal.body = marshalJSONRPC(responses[0])
	}
	if !streamable {
		refusal.status = status
		refusal.overStream = true
		if len(responses) > 0 {
			refusal.streamEvent = sseMessageEvent(refusal.body)
		}
	}
	return refusal
}

func sseMessageEvent(data []byte) []byte {
	event := make([]byte, 0, len(data)+len("event: message\ndata: \n\n"))
	event = append(event, "event: message\ndata: "...)
	event = append(event, data...)
	return append(event, "\n\n"...)
}

// With no id to answer, a JSON-RPC error alone would match no pending call, so the status carries the
// failure for any client.
func unreadableToolsRequest(service string) *mcpToolRefusal {
	return toolsRequestRefusal(http.StatusBadRequest, fmt.Sprintf("Agent Vault couldn't read this request to check which tools it calls, so it was refused. Service %q only allows some tools, so requests to it that carry a body must be uncompressed POSTs in UTF-8, and a JSON body must be valid JSON-RPC whose Mcp-Method and Mcp-Name headers, if sent, match it.", service))
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
// and anything that does not parse pass through untouched. An event stream's filter is returned, so the
// proxy can also send refusals on it. A nil allowlist hides nothing and only watches an event stream, for a
// hooked service whose refusals have to reach it.
func hideUnlistedTools(resp *http.Response, allowed map[string]bool) *sseToolsFilter {
	if resp.Body == nil || resp.Body == http.NoBody {
		return nil
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil
	}
	switch mediaType {
	case "application/json":
		if allowed != nil {
			hideUnlistedToolsInJSON(resp, allowed)
		}
	case "text/event-stream":
		filter := newSSEToolsFilter(resp.Body, allowed)
		resp.Body = filter
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		return filter
	}
	return nil
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
// stream keeps streaming. An event that grows past the cap is passed on as it arrives instead. Events the
// proxy sends itself are handed on between the upstream's, so the upstream is read on its own goroutine:
// a refusal must not wait for the server's next event.
type sseToolsFilter struct {
	upstream  io.ReadCloser
	allowed   map[string]bool
	startOnce sync.Once
	lines     chan sseLine
	injected  chan []byte
	closeOnce sync.Once
	done      chan struct{}
	// Called with the data of each endpoint event, and once when the stream is closed. Set before the first
	// Read and only called from it and from Close.
	onEndpoint func(endpoint string)
	onClose    func()

	event []byte
	out   []byte
	// The current event outgrew the cap and is streamed through until it ends.
	passthrough bool
	// The previous read stopped part way through a line longer than the reader's buffer.
	midLine bool
	// The previous line ended in a CR that was the last byte read, so an LF read next belongs to that line.
	afterCR bool
	err     error
}

type sseLine struct {
	data []byte
	err  error
}

// How many refusals can wait for the agent to read the stream before a further one falls back to a 403.
const maxPendingSSERefusals = 16

func newSSEToolsFilter(upstream io.ReadCloser, allowed map[string]bool) *sseToolsFilter {
	return &sseToolsFilter{
		upstream: upstream,
		allowed:  allowed,
		lines:    make(chan sseLine),
		injected: make(chan []byte, maxPendingSSERefusals),
		done:     make(chan struct{}),
	}
}

func (f *sseToolsFilter) Read(p []byte) (int, error) {
	f.startOnce.Do(func() { go f.readUpstream() })
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

func (f *sseToolsFilter) Close() error {
	f.closeOnce.Do(func() {
		close(f.done)
		if f.onClose != nil {
			f.onClose()
		}
	})
	return f.upstream.Close()
}

// Queues an event to hand on at the next boundary between the upstream's events, and reports whether it was
// queued: not once the stream is closed, nor when the agent has stopped reading it.
func (f *sseToolsFilter) inject(event []byte) bool {
	select {
	case <-f.done:
		return false
	default:
	}
	select {
	case f.injected <- event:
		return true
	default:
		return false
	}
}

func (f *sseToolsFilter) readUpstream() {
	src := bufio.NewReader(f.upstream)
	// A stream may open with a UTF-8 byte order mark, which SSE clients drop. Dropped here too, so the first
	// field is read by its name rather than missed: a tools/list result or an endpoint event in it.
	if bom, err := src.Peek(3); err == nil && string(bom) == "\xef\xbb\xbf" {
		_, _ = src.Discard(3)
	}
	for {
		line, err := readSSELine(src)
		select {
		case f.lines <- sseLine{data: append([]byte(nil), line...), err: err}:
		case <-f.done:
			return
		}
		if err != nil && err != bufio.ErrBufferFull {
			return
		}
	}
}

// The upstream's next line, or false when an injected event was handed on instead.
func (f *sseToolsFilter) nextLine() (sseLine, bool) {
	// Only between events, so an injected one never lands inside the upstream's.
	var injected chan []byte
	if len(f.event) == 0 && !f.passthrough && !f.midLine {
		injected = f.injected
	}
	select {
	case event := <-injected:
		f.out = event
		return sseLine{}, false
	case next := <-f.lines:
		return next, true
	case <-f.done:
		return sseLine{err: io.ErrClosedPipe}, true
	}
}

func (f *sseToolsFilter) fill() {
	next, upstream := f.nextLine()
	if !upstream {
		return
	}
	line, err := next.data, next.err
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
		event := append(f.event, line...)
		if f.onEndpoint != nil {
			if endpoint, ok := sseEndpointData(event); ok {
				f.onEndpoint(endpoint)
			}
		}
		f.out = rewriteSSEEvent(event, f.allowed)
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
	if allowed == nil {
		return event
	}
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

// The data of an endpoint event, with which a legacy SSE server tells the client where to POST its messages.
func sseEndpointData(event []byte) (string, bool) {
	var name string
	var data [][]byte
	for _, line := range splitSSELines(event) {
		if value, ok := sseFieldValue(line, "event"); ok {
			name = string(value)
		} else if value, ok := sseDataValue(line); ok {
			data = append(data, value)
		}
	}
	if name != "endpoint" || len(data) == 0 {
		return "", false
	}
	return string(bytes.Join(data, []byte("\n"))), true
}

func sseDataValue(line []byte) ([]byte, bool) {
	return sseFieldValue(line, "data")
}

func sseFieldValue(line []byte, field string) ([]byte, bool) {
	line = bytes.TrimRight(line, "\r\n")
	if !bytes.HasPrefix(line, []byte(field)) {
		return nil, false
	}
	rest := line[len(field):]
	if len(rest) == 0 {
		return rest, true
	}
	if rest[0] != ':' {
		return nil, false
	}
	return bytes.TrimPrefix(rest[1:], []byte(" ")), true
}

// The legacy SSE streams the proxy is filtering, by the URL each one's server told its client to POST to, so a
// refused POST can be answered on its stream. Keyed by session and service as well, so a refusal only ever
// reaches a stream opened in the same session to the same service.
type sseStreamRegistry struct {
	mu      sync.Mutex
	streams map[sseStreamKey]*sseToolsFilter
}

type sseStreamKey struct {
	session, service, target string
}

// Records the endpoint the stream announces, resolved against the URL the stream was opened at, until the
// stream is closed. Only the latest one is kept, so a server repeating the event holds one entry, not one
// per event.
func (r *sseStreamRegistry) watch(filter *sseToolsFilter, session, service string, streamURL url.URL) {
	var current *sseStreamKey
	forget := func() {
		if current != nil && r.streams[*current] == filter {
			delete(r.streams, *current)
		}
		current = nil
	}
	filter.onEndpoint = func(endpoint string) {
		target, err := streamURL.Parse(endpoint)
		if err != nil {
			return
		}
		key := sseStreamKey{session: session, service: service, target: sseTarget(target)}
		r.mu.Lock()
		defer r.mu.Unlock()
		forget()
		if r.streams == nil {
			r.streams = map[sseStreamKey]*sseToolsFilter{}
		}
		r.streams[key] = filter
		current = &key
	}
	filter.onClose = func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		forget()
	}
}

// Sends a legacy SSE client's refusal on the stream its POST belongs to and answers the POST with 202, as
// the server would have. The refusal is returned unchanged, a 403, when no such stream is open or it can't
// take the event.
func (r *sseStreamRegistry) deliver(session, service string, target *url.URL, refusal *mcpToolRefusal) *mcpToolRefusal {
	if !refusal.overStream {
		return refusal
	}
	r.mu.Lock()
	filter := r.streams[sseStreamKey{session: session, service: service, target: sseTarget(target)}]
	r.mu.Unlock()
	if filter == nil || (refusal.streamEvent != nil && !filter.inject(refusal.streamEvent)) {
		return refusal
	}
	return &mcpToolRefusal{status: http.StatusAccepted, reason: refusal.reason, decision: refusal.decision, code: refusal.code}
}

// The URL as the proxy forwards it, so an endpoint the server wrote with or without the default port, or in
// another case, matches the POST the client sends to it.
func sseTarget(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port) + u.EscapedPath() + "?" + u.RawQuery
}
