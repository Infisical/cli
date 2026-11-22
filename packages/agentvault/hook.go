package agentvault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

const (
	hookPayloadVersion = "1"

	// Starts once the agent's body prefix is read, and covers the hook's whole answer, headers and body.
	hookTimeout             = 3 * time.Second
	hookTLSHandshakeTimeout = 2 * time.Second
	maxHookBodyPrefix       = 1 << 20
	maxHookAnswer           = 64 << 10
	maxHookMessage          = 2 << 10
	maxHookReason           = 512
	// connect reads 8 KB of a refusal, and the JSON encoder writes each <, > and & as six bytes.
	maxNativeHookMessage = 1 << 10

	hookAllow  = "allow"
	hookDeny   = "deny"
	hookFailed = "failed"

	hookCauseTimeout      = "timeout"
	hookCauseUnreachable  = "unreachable"
	hookCauseRedirect     = "redirect"
	hookCauseTooLarge     = "too_large"
	hookCauseInvalidJSON  = "invalid_json"
	hookCauseBadDecision  = "bad_decision"
	hookCauseBrokenConfig = "broken_config"

	hookDeniedRequestMessage    = "Your organization's hook refused this request."
	hookDeniedConnectionMessage = "Your organization's hook refused this connection."
	hookFailedRequestMessage    = "The hook server for this service didn't give a usable answer, so the request was not sent."
	hookFailedConnectionMessage = "The hook server for this service didn't give a usable answer, so the connection was not opened."
	hookFailedConnectionNote    = "The hook didn't give a usable answer, so the connection wasn't opened."
	hookDeniedConnectionNote    = "The hook refused this connection"
)

var (
	errHookDenied = errors.New("the service's hook refused the request")
	errHookFailed = errors.New("the service's hook didn't give a usable answer")
)

// A nil narrowing field doesn't narrow, so a hook with none is asked about every request of its service. A field
// that doesn't fit the service's type is ignored, and an empty list is nil, since more traffic reaching the hook is
// the safe side.
type serviceHook struct {
	id string
	// Nil from servers that don't send it.
	name *string
	// Nil when the URL or secret Infisical sent can't be used, so every call fails rather than the hook being skipped.
	url     *url.URL
	secret  []byte
	methods map[string]bool
	paths   []string
	tools   map[string]bool
}

func toServiceHook(wire *api.AgentVaultServiceHook) *serviceHook {
	if wire == nil {
		return nil
	}
	hook := &serviceHook{
		id:      wire.ID,
		name:    wire.Name,
		secret:  []byte(wire.Secret),
		methods: toHookMethodSet(wire.Methods),
		paths:   toHookPathPrefixes(wire.Paths),
		tools:   toHookToolSet(wire.Tools),
	}
	parsed, err := url.Parse(wire.URL)
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && len(hook.secret) > 0 {
		hook.url = parsed
	}
	return hook
}

func toHookMethodSet(methods []string) map[string]bool {
	if len(methods) == 0 {
		return nil
	}
	return toMethodSet(methods)
}

// A list with nothing usable in it is nil, unlike toPathPrefixes: for a hook, no restriction is the safe side.
func toHookPathPrefixes(prefixes []string) []string {
	var out []string
	for _, prefix := range prefixes {
		if prefix = normalizePathPrefix(prefix); prefix != "" {
			out = append(out, strings.ToLower(prefix))
		}
	}
	return out
}

func toHookToolSet(tools []string) map[string]bool {
	if len(tools) == 0 {
		return nil
	}
	return toToolSet(tools)
}

// mcp is the parsed body of an MCP request, nil when it has none.
func (h *serviceHook) matches(svc *resolvedService, req *http.Request, mcp *hookPayloadMCP) bool {
	if svc.kind == serviceKindMCP {
		return h.tools == nil || callsAnyTool(req, mcp, h.tools)
	}
	if h.methods != nil && !h.matchesMethod(req) {
		return false
	}
	if h.paths == nil {
		return true
	}
	path := requestPath(req)
	return hookPathMatches(path, h.paths) || hookPathMatches(pathAfterSubstitutions(path, svc.substitutions), h.paths)
}

// An override header counts as the method, since a framework that honours it performs the method it names.
// So does a form POST: Rails and Laravel take the method from a `_method` field in the body. Symfony and Laravel
// also read `_method` from the query string whatever the body, and a query that can't be parsed matches.
func (h *serviceHook) matchesMethod(req *http.Request) bool {
	if h.methods[strings.ToUpper(req.Method)] {
		return true
	}
	if req.Method == http.MethodPost && isFormBody(req.Header.Get("Content-Type")) {
		return true
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return true
	}
	for _, value := range query["_method"] {
		if h.methods[strings.ToUpper(strings.TrimSpace(value))] {
			return true
		}
	}
	for _, name := range methodOverrideHeaders {
		for _, value := range req.Header.Values(name) {
			// Express's method-override takes the first of `DELETE, POST`, so every listed value is checked.
			for _, item := range strings.Split(value, ",") {
				if h.methods[strings.ToUpper(strings.TrimSpace(item))] {
					return true
				}
			}
		}
	}
	return false
}

func isFormBody(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	return mediaType == "application/x-www-form-urlencoded" || mediaType == "multipart/form-data"
}

// An ambiguous path matches, since the upstream may route it under a listed prefix. Past that check every escape
// left is benign, so decoding the whole path can't merge segments, and `/v1/%72efunds` is `/v1/refunds` upstream.
// Case is ignored, unlike the service allowlist: ASP.NET Core and IIS route paths case-insensitively, and for a
// hook a miss lets the request through unchecked, so strictness goes the unsafe way. prefixes are lowercase.
func hookPathMatches(escaped string, prefixes []string) bool {
	return isAmbiguousPath(escaped) || matchesPrefix(strings.ToLower(escaped), prefixes) ||
		matchesPrefix(strings.ToLower(decodeBenignEscapes(escaped)), prefixes)
}

// A body that can't be parsed matches, and so does a call naming no tool, so a call can't get past the hook by
// being unreadable. Mcp-Name counts too, since a gateway may route on it.
func callsAnyTool(req *http.Request, mcp *hookPayloadMCP, tools map[string]bool) bool {
	for _, name := range req.Header.Values(mcpNameHeader) {
		if tools[name] {
			return true
		}
	}
	if mcp == nil {
		return false
	}
	if !mcp.Parsed {
		return true
	}
	for _, call := range mcp.Calls {
		if call.Method == mcpMethodToolsCall && (call.Tool == "" || tools[call.Tool]) {
			return true
		}
	}
	return false
}

// Only the scheme and host are ever logged: a hook's path can carry a token.
func (h *serviceHook) origin() string {
	if h.url == nil {
		return ""
	}
	return h.url.Scheme + "://" + h.url.Host
}

// Also what the session log records for a refusal, so nothing here may hold a header or body of the request.
type hookOutcome struct {
	Decision   string `json:"decision"`
	Reason     string `json:"reason,omitempty"`
	Cause      string `json:"cause,omitempty"`
	DurationMs int64  `json:"durationMs"`
	DeliveryID string `json:"deliveryId,omitempty"`

	message string
	// Why the call failed, with the hook's URL taken out.
	err    error
	origin string
}

// Only a refusal is recorded: a row the hook allowed is described by what the upstream did.
func (o *hookOutcome) sessionLogHook() *hookOutcome {
	if o == nil || o.Decision == hookAllow {
		return nil
	}
	return &hookOutcome{Decision: o.Decision, Reason: o.Reason, Cause: o.Cause, DurationMs: o.DurationMs, DeliveryID: o.DeliveryID}
}

func (o *hookOutcome) logFields(event *zerolog.Event) *zerolog.Event {
	event = event.Str("hook", o.Decision).Int64("hookMs", o.DurationMs).Str("deliveryId", o.DeliveryID)
	if o.origin != "" {
		event = event.Str("hookUrl", o.origin)
	}
	if o.Cause != "" {
		event = event.Str("hookCause", o.Cause)
	}
	if o.Reason != "" {
		event = event.Str("hookReason", o.Reason)
	}
	if o.err != nil {
		event = event.AnErr("hookError", o.err)
	}
	return event
}

type hookPayload struct {
	Version    string                 `json:"version"`
	DeliveryID string                 `json:"deliveryId"`
	Proxy      hookPayloadProxy       `json:"proxy"`
	Hook       hookPayloadHook        `json:"hook"`
	Session    hookPayloadSession     `json:"session"`
	Service    hookPayloadService     `json:"service"`
	Request    *hookPayloadRequest    `json:"request"`
	MCP        *hookPayloadMCP        `json:"mcp"`
	Connection *hookPayloadConnection `json:"connection"`
}

type hookPayloadProxy struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type hookPayloadHook struct {
	ID   string  `json:"id"`
	Name *string `json:"name"`
}

type hookPayloadSession struct {
	ID         string                           `json:"id"`
	Label      *string                          `json:"label"`
	Actor      *api.AgentVaultSessionActor      `json:"actor"`
	OnBehalfOf *api.AgentVaultSessionOnBehalfOf `json:"onBehalfOf"`
	Metadata   map[string]string                `json:"metadata"`
}

type hookPayloadService struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Type         string             `json:"type"`
	AccessBundle *hookPayloadBundle `json:"accessBundle"`
}

type hookPayloadBundle struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type hookPayloadRequest struct {
	Method        string              `json:"method"`
	Scheme        string              `json:"scheme"`
	Host          string              `json:"host"`
	Port          string              `json:"port"`
	Path          string              `json:"path"`
	Query         string              `json:"query"`
	Headers       map[string][]string `json:"headers"`
	Body          string              `json:"body"`
	BodyEncoding  string              `json:"bodyEncoding"`
	BodyTruncated bool                `json:"bodyTruncated"`
}

type hookPayloadMCP struct {
	Calls  []hookMCPCall `json:"calls"`
	Parsed bool          `json:"parsed"`
}

type hookMCPCall struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Tool   string          `json:"tool,omitempty"`
}

type hookPayloadConnection struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Database string `json:"database"`
}

type hookAnswer struct {
	Decision string `json:"decision"`
	Message  string `json:"message"`
	Reason   string `json:"reason"`
}

type hookClient struct {
	client *http.Client
}

// Proxy is nil so a corporate proxy never sees the payload, which holds the agent's request body.
func newHookClient(rootCAs *x509.CertPool) *hookClient {
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: hookTimeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: hookTLSHandshakeTimeout,
		TLSClientConfig:     &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
	}
	return &hookClient{client: &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// One pool for the life of the proxy, so hook calls reuse connections rather than paying a handshake each.
var sharedHookClient = sync.OnceValue(func() *hookClient { return newHookClient(nil) })

func (ps *proxyServer) newHookPayload(svc *resolvedService, found cacheLookup) hookPayload {
	payload := hookPayload{
		Version: hookPayloadVersion,
		Proxy:   hookPayloadProxy{ID: ps.opts.ProxyID, Version: util.CLI_VERSION},
		// Always an object, so a hook server can read a key without first checking for null.
		Session: hookPayloadSession{ID: found.sessionID, Metadata: map[string]string{}},
		Service: hookPayloadService{ID: svc.id, Name: svc.name, Type: toServiceKind(svc.kind)},
	}
	if hook := svc.hook; hook != nil {
		payload.Hook = hookPayloadHook{ID: hook.id, Name: hook.name}
	}
	if session := found.session; session != nil {
		actor := session.Actor
		payload.Session.Label, payload.Session.Actor, payload.Session.OnBehalfOf = session.Label, &actor, session.OnBehalfOf
		if session.Metadata != nil {
			payload.Session.Metadata = session.Metadata
		}
	}
	if svc.accessBundleID != "" || svc.accessBundleName != "" {
		payload.Service.AccessBundle = &hookPayloadBundle{ID: svc.accessBundleID, Name: svc.accessBundleName}
	}
	return payload
}

// Standard Webhooks: the id and timestamp are signed with the body, so neither can be replaced on a replay.
func signHook(secret []byte, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id))
	mac.Write([]byte{'.'})
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// ask never returns nil, and anything but a well-formed allow or deny is a failure, so a hook can only let a
// request through by saying so.
func (c *hookClient) ask(parent context.Context, hook *serviceHook, payload *hookPayload) *hookOutcome {
	start := time.Now()
	id, err := uuid.NewV7()
	if err != nil {
		id = uuid.New()
	}
	out := &hookOutcome{DeliveryID: id.String(), origin: hook.origin()}
	defer func() { out.DurationMs = time.Since(start).Milliseconds() }()

	fail := func(cause string, err error) *hookOutcome {
		out.Decision, out.Cause, out.err = hookFailed, cause, err
		return out
	}
	if hook.url == nil {
		return fail(hookCauseBrokenConfig, errors.New("the hook URL or signing secret Infisical sent can't be used"))
	}

	payload.DeliveryID = out.DeliveryID
	body, ok := encodeJSON(payload)
	if !ok {
		return fail(hookCauseBrokenConfig, errors.New("the request could not be encoded for the hook"))
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	ctx, cancel := context.WithTimeout(parent, hookTimeout)
	defer cancel()
	// A bytes.Reader sets GetBody, which with Idempotency-Key lets Go resend on a pooled connection the hook closed.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.url.String(), bytes.NewReader(body))
	if err != nil {
		return fail(hookCauseBrokenConfig, errors.New("the hook URL Infisical sent can't be used"))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "infisical-agent-vault-proxy/"+util.CLI_VERSION)
	req.Header.Set("webhook-id", out.DeliveryID)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", signHook(hook.secret, out.DeliveryID, timestamp, body))
	req.Header.Set("Idempotency-Key", out.DeliveryID)

	resp, err := c.client.Do(req)
	if err != nil {
		return fail(hookTransportCause(ctx, err))
	}
	defer resp.Body.Close()

	// The Location header is never read: it is the hook server's URL, path and all.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fail(hookCauseRedirect, fmt.Errorf("it answered with a redirect (%d), which the proxy doesn't follow", resp.StatusCode))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fail("status_"+strconv.Itoa(resp.StatusCode), fmt.Errorf("it answered with status %d", resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxHookAnswer+1))
	if err != nil {
		return fail(hookTransportCause(ctx, err))
	}
	if len(raw) > maxHookAnswer {
		return fail(hookCauseTooLarge, fmt.Errorf("its answer is larger than %d KB", maxHookAnswer>>10))
	}
	var answer hookAnswer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return fail(hookCauseInvalidJSON, errors.New("its answer isn't a JSON object with string fields"))
	}
	if answer.Decision != hookAllow && answer.Decision != hookDeny {
		return fail(hookCauseBadDecision, errors.New(`its answer has no decision of "allow" or "deny"`))
	}
	out.Decision = answer.Decision
	out.message = cleanHookText(answer.Message, maxHookMessage)
	out.Reason = cleanHookText(answer.Reason, maxHookReason)
	return out
}

// A url.Error names the whole hook URL, so only the error inside it is kept.
func hookTransportCause(ctx context.Context, err error) (string, error) {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	// Go parses a redirect's Location before CheckRedirect runs, and quotes it when it can't.
	if strings.HasPrefix(err.Error(), "failed to parse Location header") {
		return hookCauseRedirect, errors.New("it answered with a redirect, which the proxy doesn't follow")
	}
	var netErr net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return hookCauseTimeout, err
	}
	return hookCauseUnreachable, err
}

// Control and invisible characters are dropped, line breaks become spaces, and the text is cut on a character
// boundary, so a hook's words can't forge log lines or hide text from whoever reads them.
func cleanHookText(s string, limit int) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "") {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == '\u2028' || r == '\u2029':
			r = ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		}
		if b.Len()+utf8.RuneLen(r) > limit {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// Cut on a character boundary, so the text stays valid.
func capText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

// The agent's body up to limit bytes, and whether it holds more. The request keeps its whole body: one the proxy
// already holds is reused, one that fits is held so an OAuth retry can send it again, and a longer one is put back
// in front of the rest of the stream.
func hookBodyPrefix(req *http.Request, limit int) ([]byte, bool, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, false, nil
	}
	if buffered, ok := req.Body.(*bufferedBody); ok {
		if len(buffered.data) > limit {
			return buffered.data[:limit], true, nil
		}
		return buffered.data, false, nil
	}
	original := req.Body
	read, err := io.ReadAll(io.LimitReader(original, int64(limit)+1))
	if err != nil {
		req.Body = rechainedBody{Reader: io.MultiReader(bytes.NewReader(read), erroringReader{err}), Closer: original}
		return nil, false, errBodyUnreadable
	}
	if len(read) > limit {
		req.Body = rechainedBody{Reader: io.MultiReader(bytes.NewReader(read), original), Closer: original}
		return read[:limit], true, nil
	}
	_ = original.Close()
	if len(read) == 0 {
		req.Body = http.NoBody
	} else {
		req.Body = &bufferedBody{Reader: bytes.NewReader(read), data: read}
	}
	return read, false, nil
}

// UTF-8 text when the prefix is, else base64. A compressed body is always base64: its bytes are not the text.
func hookBodyText(prefix []byte, truncated bool, header http.Header) (string, string) {
	encoding := header.Get("Content-Encoding")
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		text := prefix
		if truncated {
			text = trimPartialRune(text)
		}
		if utf8.Valid(text) {
			return string(text), "utf8"
		}
	}
	return base64.StdEncoding.EncodeToString(prefix), "base64"
}

// A prefix cut part way through a character would otherwise fail the UTF-8 check and go out as base64.
func trimPartialRune(b []byte) []byte {
	for i := 1; i <= utf8.UTFMax && i <= len(b); i++ {
		if utf8.RuneStart(b[len(b)-i]) {
			if !utf8.FullRune(b[len(b)-i:]) {
				return b[:len(b)-i]
			}
			return b
		}
	}
	return b
}

func hookHeaders(header http.Header) map[string][]string {
	out := make(map[string][]string, len(header))
	for name, values := range header {
		key := strings.ToLower(name)
		out[key] = append(out[key], values...)
	}
	return out
}

// The messages in a body the proxy read whole, so a refusal can answer each one. A body declared in a charset other
// than UTF-8 is left unparsed, for the reason requestMediaType gives: the server may decode a different tool name.
func hookMCPOf(prefix []byte, truncated bool, header http.Header) (*hookPayloadMCP, []jsonrpcMessage) {
	out := &hookPayloadMCP{Calls: []hookMCPCall{}}
	if _, isUTF8 := requestMediaType(header); truncated || !isUTF8 {
		return out, nil
	}
	messages, ok := parseJSONRPCMessages(prefix)
	if !ok {
		return out, nil
	}
	for _, message := range messages {
		out.Calls = append(out.Calls, hookMCPCall{ID: message.id, Method: message.Method, Tool: message.Tool})
	}
	out.Parsed = true
	return out, messages
}

// askHook runs after the proxy's own checks and before substitutions, custom headers and the credential, so the
// hook judges what the agent sent and never sees a value Infisical holds. A request the hook's narrowing doesn't
// pick is let through without asking.
func (ps *proxyServer) askHook(req *http.Request, t tunnel, svc *resolvedService, found cacheLookup, outcome *forwardOutcome) error {
	hook := svc.hook
	// Judged before the body is read, which only MCP tool narrowing needs.
	if svc.kind != serviceKindMCP && !hook.matches(svc, req, nil) {
		return nil
	}
	// Reading a streaming gRPC body would wait for the call to end, so the hook is asked without it.
	var prefix []byte
	truncated := true
	streamed := streamsGRPCBody(req, t)
	if !streamed {
		var err error
		if prefix, truncated, err = hookBodyPrefix(req, maxHookBodyPrefix); err != nil {
			return err
		}
	}
	var mcp *hookPayloadMCP
	var messages []jsonrpcMessage
	if svc.kind == serviceKindMCP {
		mcp, messages = hookMCPOf(prefix, truncated, req.Header)
		inspected := mcp
		if len(prefix) == 0 && !streamed {
			inspected = nil
		}
		if !hook.matches(svc, req, inspected) {
			return nil
		}
	}
	body, encoding := hookBodyText(prefix, truncated, req.Header)
	payload := ps.newHookPayload(svc, found)
	payload.MCP = mcp
	payload.Request = &hookPayloadRequest{
		Method:        req.Method,
		Scheme:        t.scheme,
		Host:          strings.ToLower(t.hostname),
		Port:          t.port,
		Path:          requestPath(req),
		Query:         req.URL.RawQuery,
		Headers:       hookHeaders(req.Header),
		Body:          body,
		BodyEncoding:  encoding,
		BodyTruncated: truncated,
	}

	result := sharedHookClient().ask(req.Context(), hook, &payload)
	outcome.hook = result
	if result.Decision == hookAllow {
		return nil
	}

	denied := result.Decision == hookDeny
	if denied && result.message == "" {
		result.message = hookDeniedRequestMessage
	}
	// A JSON-RPC client needs a JSON-RPC answer; a GET for the event stream or a DELETE has no message to answer.
	if svc.kind == serviceKindMCP && strings.EqualFold(req.Method, http.MethodPost) {
		refusal := hookFailedMCPRefusal(messages, payload.MCP.Parsed, isBatch(prefix), streamableHTTPClient(req))
		if denied {
			refusal = hookDeniedMCPRefusal(result.message, messages, payload.MCP.Parsed, isBatch(prefix), streamableHTTPClient(req))
		}
		return ps.sseStreams.deliver(t.sessionToken, svc.id, req.URL, refusal)
	}
	if denied {
		return errHookDenied
	}
	return errHookFailed
}

func isBatch(body []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(body), []byte("["))
}

// Once per connection, before the tunnel opens. Open connections are not asked again.
func (ps *proxyServer) askNativeHook(ctx context.Context, svc *resolvedService, found cacheLookup) *hookOutcome {
	payload := ps.newHookPayload(svc, found)
	payload.Connection = &hookPayloadConnection{
		Host:     svc.native.host,
		Port:     strconv.Itoa(svc.native.port),
		Database: svc.native.database,
	}
	return sharedHookClient().ask(ctx, svc.hook, &payload)
}

func nativeHookRefusal(result *hookOutcome) nativeRefusal {
	if result.Decision == hookDeny {
		body := capText(result.message, maxNativeHookMessage)
		if body == "" {
			body = hookDeniedConnectionMessage
		}
		note := hookDeniedConnectionNote + "."
		if detail := firstNonEmpty(result.Reason, result.message); detail != "" {
			note = hookDeniedConnectionNote + ": " + detail
		}
		return nativeRefusal{decision: decisionBlocked, status: http.StatusForbidden, code: errorCodeHookDenied, body: body, note: note, hook: result}
	}
	return nativeRefusal{decision: decisionError, status: http.StatusServiceUnavailable, code: errorCodeHookFailed,
		body: hookFailedConnectionMessage, note: hookFailedConnectionNote, hook: result}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
