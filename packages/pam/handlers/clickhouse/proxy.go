package clickhouse

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Brokered over ClickHouse's HTTP interface rather than the native protocol on 9000, where a statement is
// text and can be blocked and recorded without parsing a version-gated binary format. The client's own
// credentials are dropped and the account's injected, so nothing it holds works outside a recorded session.
type ClickHouseProxyConfig struct {
	TargetAddr string
	Username   string
	Password   string
	Database   string
	EnableTLS  bool
	TLSConfig  *tls.Config

	SessionID       string
	SessionLogger   session.SessionLogger
	BlockedCommands []*regexp.Regexp
}

const (
	// How much of a body is decompressed and matched against the policy. A statement leads the body, so an
	// INSERT's rows stream past unbuffered, but padding could bury one: a blocking account refuses the rest.
	maxInspectBytes = 1 << 20
	// What of a statement reaches the recording, so one bulk INSERT can't fill a session log
	maxLoggedStatementBytes = 8 << 10
	maxLoggedErrorBytes     = 8 << 10

	dialTimeout      = 30 * time.Second
	testQueryTimeout = 30 * time.Second
)

// ClickHouse error codes, so a driver reports a gateway refusal the way it reports a server refusal
const (
	codeNotImplemented = 48
	codeNetworkError   = 210
	codeAccessDenied   = 497
)

var errorNames = map[int]string{
	codeNotImplemented: "NOT_IMPLEMENTED",
	codeNetworkError:   "NETWORK_ERROR",
	codeAccessDenied:   "ACCESS_DENIED",
}

// Every way a client can present its own identity
var strippedAuthHeaders = []string{
	"Authorization",
	"X-ClickHouse-User",
	"X-ClickHouse-Key",
	"X-ClickHouse-SSL-Certificate-Auth",
}

var strippedAuthParams = []string{"user", "password"}

var strippedExecutionParams = []string{"role"}

var allowedPaths = map[string]bool{"/": true, "/ping": true}

type ClickHouseProxy struct {
	config  ClickHouseProxyConfig
	reverse *httputil.ReverseProxy
}

type stateKey struct{}

type requestState struct {
	statement string
	started   time.Time
}

func NewClickHouseProxy(config ClickHouseProxyConfig) *ClickHouseProxy {
	proxy := &ClickHouseProxy{config: config}
	proxy.reverse = &httputil.ReverseProxy{
		Director:       proxy.director,
		Transport:      newTransport(config),
		ModifyResponse: proxy.modifyResponse,
		ErrorHandler:   proxy.handleUpstreamError,
		// Progress and long-running results reach the client as they arrive
		FlushInterval: -1,
	}
	return proxy
}

func newTransport(config ClickHouseProxyConfig) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       config.TLSConfig,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func (p *ClickHouseProxy) scheme() string {
	if p.config.EnableTLS {
		return "https"
	}
	return "http"
}

func (p *ClickHouseProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	l := log.With().Str("sessionId", p.config.SessionID).Str("resourceType", "clickhouse").Logger()

	server := &http.Server{
		Handler:           p.handler(l),
		ReadHeaderTimeout: 30 * time.Second,
	}

	listener := newSingleConnListener(clientConn)

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		listener.Close()
		server.Close()
	}()

	if err := server.Serve(listener); err != nil && !isListenerDone(err) {
		l.Debug().Err(err).Msg("ClickHouse proxy stopped")
	}
	return nil
}

func (p *ClickHouseProxy) handler(l zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedPaths[r.URL.Path] {
			l.Info().Str("path", r.URL.Path).Msg("Refused a path outside the query endpoint")
			writeClickHouseError(w, http.StatusNotFound, codeNotImplemented,
				fmt.Sprintf("This session serves ClickHouse's query endpoint, so %q is not available here.", r.URL.Path))
			return
		}

		statement, body, err := p.inspect(r)
		if err != nil {
			writeClickHouseError(w, http.StatusBadRequest, codeNotImplemented, err.Error())
			return
		}

		if blocked := p.blockedBy(statement); blocked != nil {
			p.logStatement(statement, fmt.Sprintf("BLOCKED: %s", blocked.String()))
			l.Info().Str("pattern", blocked.String()).Msg("Blocked a statement by policy")
			writeClickHouseError(w, http.StatusForbidden, codeAccessDenied,
				"This statement is blocked by the command blocking policy on this account.")
			return
		}

		r.Body = body
		state := &requestState{statement: statement, started: time.Now()}
		p.reverse.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), stateKey{}, state)))
	})
}

type bodyReadCloser struct {
	io.Reader
	io.Closer
}

// Returns the statement and a body that still replays in full. ClickHouse concatenates `query` and the body.
func (p *ClickHouseProxy) inspect(r *http.Request) (string, io.ReadCloser, error) {
	queryParam := strings.TrimSpace(r.URL.Query().Get("query"))

	if r.Body == nil || r.ContentLength == 0 {
		return queryParam, http.NoBody, nil
	}

	// ClickHouse's own block compression is opaque to anything but a ClickHouse client
	if r.URL.Query().Get("decompress") == "1" {
		return "", nil, fmt.Errorf(
			"this session cannot read a ClickHouse-compressed request body, so decompress=1 is not supported here. " +
				"Send the statement uncompressed or with Content-Encoding: gzip")
	}

	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity", "gzip", "deflate":
	default:
		return "", nil, fmt.Errorf(
			"this session cannot read a %q-encoded request body, so the command blocking policy could not be applied to it. "+
				"Use gzip, deflate, or no compression", encoding)
	}

	// One byte past the window is what tells a body that fits from one that was cut short
	head := make([]byte, maxInspectBytes+1)
	n, err := io.ReadFull(r.Body, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", nil, fmt.Errorf("the gateway could not read the request body: %v", err)
	}
	head = head[:n]

	forwarded := bodyReadCloser{Reader: io.MultiReader(bytes.NewReader(head), r.Body), Closer: r.Body}

	decoded, decodedOverflow, decodeErr := decodeHead(head, encoding)
	if decodeErr != nil {
		return "", nil, fmt.Errorf(
			"the gateway could not decompress the request body to apply the command blocking policy: %v", decodeErr)
	}

	if (len(head) > maxInspectBytes || decodedOverflow) && len(p.config.BlockedCommands) > 0 {
		return "", nil, fmt.Errorf(
			"this account blocks commands, so a request body larger than %d MB is refused: the gateway has to read "+
				"the whole statement to apply the policy. Send the data in smaller batches",
			maxInspectBytes>>20)
	}

	return joinStatement(queryParam, string(decoded)), forwarded, nil
}

func joinStatement(queryParam string, body string) string {
	body = strings.TrimSpace(body)
	switch {
	case queryParam == "":
		return body
	case body == "":
		return queryParam
	default:
		return queryParam + "\n" + body
	}
}

func decodeHead(head []byte, encoding string) ([]byte, bool, error) {
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(head))
		if err != nil {
			return nil, false, err
		}
		defer reader.Close()
		return readTolerant(reader)
	case "deflate":
		// "deflate" is sent both as zlib and as raw deflate, so both are tried
		if reader, err := zlib.NewReader(bytes.NewReader(head)); err == nil {
			defer reader.Close()
			if decoded, overflow, readErr := readTolerant(reader); readErr == nil {
				return decoded, overflow, nil
			}
		}
		reader := flate.NewReader(bytes.NewReader(head))
		defer reader.Close()
		return readTolerant(reader)
	default:
		return head, len(head) > maxInspectBytes, nil
	}
}

// The head is a deliberate prefix, so a stream ending mid-frame is expected rather than an error
func readTolerant(r io.Reader) ([]byte, bool, error) {
	decoded, err := io.ReadAll(io.LimitReader(r, maxInspectBytes+1))
	overflow := len(decoded) > maxInspectBytes
	if overflow {
		decoded = decoded[:maxInspectBytes]
	}
	if len(decoded) > 0 || err == nil || err == io.EOF {
		return decoded, overflow, nil
	}
	return nil, false, err
}

func (p *ClickHouseProxy) director(req *http.Request) {
	req.URL.Scheme = p.scheme()
	req.URL.Host = p.config.TargetAddr
	req.Host = p.config.TargetAddr

	query := req.URL.Query()
	for _, param := range append(append([]string{}, strippedAuthParams...), strippedExecutionParams...) {
		query.Del(param)
	}
	if p.config.Database != "" {
		query.Set("database", p.config.Database)
	}
	req.URL.RawQuery = query.Encode()

	for _, header := range strippedAuthHeaders {
		req.Header.Del(header)
	}
	req.Header.Set("X-ClickHouse-User", p.config.Username)
	if p.config.Password != "" {
		req.Header.Set("X-ClickHouse-Key", p.config.Password)
	}
	req.Header["X-Forwarded-For"] = nil
}

func (p *ClickHouseProxy) modifyResponse(resp *http.Response) error {
	state, ok := resp.Request.Context().Value(stateKey{}).(*requestState)
	if !ok || state == nil {
		return nil
	}

	if resp.StatusCode >= http.StatusBadRequest {
		original := resp.Body
		head, _ := io.ReadAll(io.LimitReader(original, maxLoggedErrorBytes))
		resp.Body = bodyReadCloser{Reader: io.MultiReader(bytes.NewReader(head), original), Closer: original}
		p.logStatement(state.statement, fmt.Sprintf("ERROR: %s: %s", resp.Status, strings.TrimSpace(string(head))))
		return nil
	}

	// Recorded once the body has finished, so a transfer that dies mid-stream is not logged as a success
	resp.Body = &completionLoggingBody{ReadCloser: resp.Body, onDone: func(err error) {
		outcome := summarize(resp, time.Since(state.started))
		if err != nil {
			outcome = fmt.Sprintf("INTERRUPTED: %s, %v", outcome, err)
		}
		p.logStatement(state.statement, outcome)
	}}
	return nil
}

type completionLoggingBody struct {
	io.ReadCloser
	onDone func(error)
	once   sync.Once
}

func (b *completionLoggingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		finished := err
		if errors.Is(err, io.EOF) {
			finished = nil
		}
		b.once.Do(func() { b.onDone(finished) })
	}
	return n, err
}

func (b *completionLoggingBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { b.onDone(errors.New("the response was closed before it finished")) })
	return err
}

func summarize(resp *http.Response, elapsed time.Duration) string {
	parts := []string{resp.Status}

	if raw := resp.Header.Get("X-ClickHouse-Summary"); raw != "" {
		var summary struct {
			ReadRows    string `json:"read_rows"`
			WrittenRows string `json:"written_rows"`
			ResultRows  string `json:"result_rows"`
		}
		if json.Unmarshal([]byte(raw), &summary) == nil {
			for _, counter := range [][2]string{
				{summary.ResultRows, "row(s) returned"},
				{summary.WrittenRows, "row(s) written"},
				{summary.ReadRows, "row(s) read"},
			} {
				if counter[0] != "" && counter[0] != "0" {
					parts = append(parts, counter[0]+" "+counter[1])
				}
			}
		}
	}

	return strings.Join(append(parts, fmt.Sprintf("%dms", elapsed.Milliseconds())), ", ")
}

func (p *ClickHouseProxy) handleUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	log.Error().Err(err).
		Str("sessionId", p.config.SessionID).
		Str("path", r.URL.Path).
		Msg("Failed to reach ClickHouse")

	if state, ok := r.Context().Value(stateKey{}).(*requestState); ok && state != nil {
		p.logStatement(state.statement, fmt.Sprintf("ERROR: %s", err))
	}

	writeClickHouseError(w, http.StatusBadGateway, codeNetworkError,
		fmt.Sprintf("The gateway could not reach ClickHouse: %v", err))
}

func (p *ClickHouseProxy) blockedBy(statement string) *regexp.Regexp {
	if statement == "" {
		return nil
	}
	for _, pattern := range p.config.BlockedCommands {
		if pattern.MatchString(statement) {
			return pattern
		}
	}
	return nil
}

func (p *ClickHouseProxy) logStatement(input string, output string) {
	if p.config.SessionLogger == nil || strings.TrimSpace(input) == "" {
		return
	}
	if len(input) > maxLoggedStatementBytes {
		input = input[:maxLoggedStatementBytes] + "... [truncated]"
	}
	if err := p.config.SessionLogger.LogEntry(session.SessionLogEntry{
		Timestamp: time.Now(),
		Input:     input,
		Output:    output,
	}); err != nil {
		log.Error().Err(err).Str("sessionId", p.config.SessionID).Msg("Failed to log a ClickHouse statement")
	}
}

func writeClickHouseError(w http.ResponseWriter, status int, code int, message string) {
	name, ok := errorNames[code]
	if !ok {
		name = "UNKNOWN"
	}
	body := fmt.Sprintf("Code: %d. DB::Exception: %s (%s)\n", code, message, name)

	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Header().Set("X-ClickHouse-Exception-Code", strconv.Itoa(code))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// Runs one statement as the account, so the test proves the login a session uses, not just an open port.
func TestConnection(ctx context.Context, config ClickHouseProxyConfig) error {
	target := (&ClickHouseProxy{config: config}).scheme() + "://" + config.TargetAddr + "/"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader("SELECT 1"))
	if err != nil {
		return err
	}

	query := req.URL.Query()
	if config.Database != "" {
		query.Set("database", config.Database)
	}
	req.URL.RawQuery = query.Encode()

	req.Header.Set("X-ClickHouse-User", config.Username)
	if config.Password != "" {
		req.Header.Set("X-ClickHouse-Key", config.Password)
	}

	transport := newTransport(config)
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: testQueryTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxLoggedErrorBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("clickhouse rejected the connection: %s", firstLine(string(body), resp.Status))
	}
	return nil
}

func firstLine(body string, fallback string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return fallback
	}
	if idx := strings.IndexByte(trimmed, '\n'); idx != -1 {
		return strings.TrimSpace(trimmed[:idx])
	}
	return trimmed
}
