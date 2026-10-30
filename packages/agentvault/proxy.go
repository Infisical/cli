package agentvault

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	// Not 17322: the shipped `secrets agent-proxy start` already defaults to it, and both are expected to
	// run on one box.
	DefaultPort = 17323

	tlsHandshakeTimeout = 10 * time.Second

	// No server-level Read/WriteTimeout: they would cut CONNECT hijacks and long streaming responses.
	frontReadHeaderTimeout = 30 * time.Second
	frontIdleTimeout       = 5 * time.Minute

	// The write timeouts are absolute deadlines set at request start, so they bound only a response that
	// has produced nothing yet.
	tunnelReadHeaderTimeout = 10 * time.Second
	tunnelReadTimeout       = 60 * time.Second
	tunnelWriteTimeout      = 30 * time.Minute
	tunnelIdleTimeout       = 2 * time.Minute

	plainReadTimeout  = 60 * time.Second
	plainWriteTimeout = 30 * time.Minute

	// Refreshed on every flushed chunk, so a response lives as long as it keeps producing.
	streamIdleTimeout = 5 * time.Minute

	maxRequestHeaderBytes = 1 << 20

	maxConcurrentConns = 512

	maxLoggedPathLen   = 2048
	maxLoggedMethodLen = 32
)

var errHostBlocked = errors.New("host blocked by policy")

var errOpaqueTarget = errors.New("the request target must be a path; opaque forms are not forwarded")

// Wraps a resolve failure so the tunnel can tell it from an upstream failure without reading the text.
var errSessionResolve = errors.New("failed to resolve the session")

const (
	decisionBrokered    = "brokered"
	decisionPassthrough = "passthrough"
	decisionBlocked     = "blocked"
	decisionError       = "error"
)

type Options struct {
	Port int
	// Empty binds every interface.
	ListenHost string
	DataDir    string
	ProxyToken func() string
	ProxyID    string
	ProxyName  string
	OwnCa      *OwnCa
	// Nil leaves the SOCKS5 listener off.
	Socks5 *Socks5Options

	OnReady func()
}

type proxyServer struct {
	opts        Options
	ca          *caManager
	cache       *sessionCache
	sessionLogs *sessionLogRecorder
	transport   http.RoundTripper
	// SOCKS5 traffic that no service names goes out through this one, which refuses private destinations
	// when it dials. Its own pool, so it never reuses a connection the unchecked transport opened.
	guardedTransport   http.RoundTripper
	socks5AllowPrivate bool
	lastNotWebWarn     atomic.Int64

	configMu sync.RWMutex
	config   ProxyConfig

	// What Start loaded, so a settings change is persisted from memory. A re-read at that instant could find
	// the file gone and write it back without the token. Only tick touches it after Start.
	persisted persistedState
	legacy    bool

	saturationOnce sync.Once
}

func (ps *proxyServer) currentConfig() ProxyConfig {
	ps.configMu.RLock()
	defer ps.configMu.RUnlock()
	return ps.config
}

func (ps *proxyServer) setConfig(next ProxyConfig) bool {
	ps.configMu.Lock()
	defer ps.configMu.Unlock()
	if ps.config == next {
		return false
	}
	ps.config = next
	return true
}

func (ps *proxyServer) pollInterval() time.Duration {
	interval := ps.currentConfig().PollInterval
	if interval <= 0 {
		interval = 60
	}
	return time.Duration(interval) * time.Second
}

func newUpstreamTransport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		// HTTP/1.1 upstream, as the other two proxies do. ForceAttemptHTTP2 alone does not achieve that:
		// with no TLS config or dialer of our own, h2 is enabled regardless and the empty map is what
		// turns it off. One shared h2 connection per host would also fail several brokered requests
		// together when an upstream restarts.
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
	}
}

// ProxyAuthUsername is the fixed username half of the proxy URL handed to an agent. It carries no
// meaning: the token is the password. Clients only send Proxy-Authorization when both halves are
// present, and the username is the half tools print rather than mask.
const ProxyAuthUsername = "x-agent-vault"

// requestSessionToken reads the session token off Proxy-Authorization, whose password half is what an
// agent's HTTPS_PROXY URL carries. The username is ignored.
func requestSessionToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		return "", false
	}
	_, sessionToken, ok := parseProxyBasicAuth(header)
	if !ok || sessionToken == "" {
		return "", false
	}
	return sessionToken, true
}

func writeProxyAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="Infisical Agent Vault"`)
	http.Error(w, "a session token is required", http.StatusProxyAuthRequired)
}

func (ps *proxyServer) dispatch(w http.ResponseWriter, r *http.Request) {
	if ps.serveSelfEndpoint(w, r) {
		return
	}
	if r.Method == http.MethodConnect {
		ps.handleConnect(w, r)
		return
	}
	ps.handlePlainForward(w, r)
}

// denyAtGate answers a request refused before the tunnel or the forward, and says so in the log. The
// cache already reports both conditions when its poll loop meets them, but the request that is
// actually turned away said nothing, which is the one an operator is looking for. The session key is
// the hash the cache is keyed on, so lines can be correlated without the token appearing anywhere.
const proxyRevokedBody = "this proxy's access has been revoked"

func (ps *proxyServer) denyAtGate(w http.ResponseWriter, sessionToken, hostname, port string, err error) {
	refusal := classifyGateRefusal(err)
	refusal.event.
		Str("host", net.JoinHostPort(hostname, port)).
		Str("sessionKey", sessionKey(sessionToken)).
		Str("decision", refusal.decision).
		Int("status", refusal.status).
		Msg(refusal.msg)
	http.Error(w, refusal.body, refusal.status)
}

type gateRefusal struct {
	event    *zerolog.Event
	decision string
	status   int
	body     string
	msg      string
}

// Shared by both doors so a refused session reads the same in the log whichever way it arrived.
func classifyGateRefusal(err error) gateRefusal {
	if isProxyTokenRejected(err) {
		return gateRefusal{log.Error().Err(err), decisionError, http.StatusServiceUnavailable, proxyRevokedBody,
			"agent-vault: refused, Infisical rejected this proxy's token"}
	}
	if isSessionGone(err) {
		return gateRefusal{log.Warn(), decisionBlocked, http.StatusForbidden, "the session is no longer valid",
			"agent-vault: refused, the session is no longer valid"}
	}
	return gateRefusal{log.Error().Err(err), decisionError, http.StatusBadGateway, "failed to resolve the session",
		"agent-vault: refused, the session could not be resolved"}
}

func (ps *proxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Everything that can produce an HTTP status happens before Hijack: once hijacked, no status can be sent.
	sessionToken, ok := requestSessionToken(r)
	if !ok {
		writeProxyAuthChallenge(w)
		return
	}

	hostname, port, err := parseConnectTarget(r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid CONNECT target %q", r.Host), http.StatusBadRequest)
		return
	}

	// Resolve before the leaf minting further down, so an unauthenticated caller cannot make the proxy work
	// on their behalf.
	if _, err := ps.cache.get(sessionToken); err != nil {
		ps.denyAtGate(w, sessionToken, hostname, port, err)
		return
	}

	// Private and link-local addresses are reachable, deliberately: an internal API inside the operator's
	// own network is a first-class destination.

	leaf, err := ps.ca.mintLeaf(hostname)
	if err != nil {
		http.Error(w, "failed to mint a certificate", http.StatusInternalServerError)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	ps.serveIntercepted(clientConn, tunnel{hostname: hostname, port: port, sessionToken: sessionToken}, leaf)
}

// tunnel is what a connection was opened for, fixed before any byte of the agent's request is read.
type tunnel struct {
	scheme       string
	hostname     string
	port         string
	sessionToken string
	viaSocks5    bool
}

// serveIntercepted takes over a connection the agent has been told is open to the target, from either door.
// Node's fetch tunnels http:// targets too and speaks plaintext inside, where every other client sends
// absolute-form. A tunnel is opaque bytes to an ordinary proxy, so that works everywhere else; here the
// first byte decides: a TLS record starts with 0x16, anything else is plain HTTP and takes the same path
// as absolute-form. The port stays the one the tunnel named, so a service still only matches if its
// pattern covers that port.
func (ps *proxyServer) serveIntercepted(conn net.Conn, t tunnel, leaf tls.Certificate) {
	buffered := newBufferedConn(conn)
	_ = conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	first, err := buffered.reader.Peek(1)
	if err != nil {
		// Nothing arrived: a protocol where the server speaks first, such as SMTP or MySQL.
		ps.warnNotWebTraffic(t, "the client sent nothing")
		return
	}
	if first[0] != tlsRecordTypeHandshake {
		// A SOCKS5 provider sends every TCP flow here, so SSH or a database driver would otherwise get an
		// HTTP 400 and leave no trace above debug level.
		if t.viaSocks5 {
			if head, err := buffered.reader.Peek(4); err != nil || !looksLikeHTTPRequest(head) {
				ps.warnNotWebTraffic(t, "the client didn't send TLS or an HTTP request")
				return
			}
		}
		_ = conn.SetDeadline(time.Time{})
		t.scheme = "http"
		ps.serveTunnel(buffered, t)
		return
	}

	tlsConn := tls.Server(buffered, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
		// http/1.1 only. An h2-only client fails ALPN here, which is a documented unsupported case rather than
		// something to paper over with a silent downgrade.
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Debug().Err(err).Str("host", net.JoinHostPort(t.hostname, t.port)).Msg("agent-vault: tunnel TLS handshake failed")
		// An HTTP/2-only client such as gRPC, or one that doesn't trust the proxy's CA, ends here.
		ps.warnNotWebTraffic(t, "the TLS handshake failed: "+err.Error())
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	t.scheme = "https"
	ps.serveTunnel(tlsConn, t)
}

const tlsRecordTypeHandshake = 0x16

// Any method in capitals passes, so WebDAV's PROPFIND or MKCOL reach the HTTP parser like GET does. Every
// method is at least three letters, so a space can only come fourth. SSH ("SSH-") and binary protocols fail.
func looksLikeHTTPRequest(head []byte) bool {
	for i, c := range head {
		if c == ' ' && i == 3 {
			continue
		}
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

const notWebTrafficWarnEvery = time.Minute

// Only the SOCKS5 door warns: the HTTP door is reached by clients that chose to use a web proxy, and its
// logs stay as they were. Rate limited, since a sandbox retrying a git push over SSH repeats it constantly.
func (ps *proxyServer) warnNotWebTraffic(t tunnel, reason string) {
	if !t.viaSocks5 {
		return
	}
	now := time.Now().UnixNano()
	last := ps.lastNotWebWarn.Load()
	if now-last < int64(notWebTrafficWarnEvery) || !ps.lastNotWebWarn.CompareAndSwap(last, now) {
		return
	}
	log.Warn().
		Str("door", "socks5").
		Str("host", net.JoinHostPort(t.hostname, t.port)).
		Str("reason", reason).
		Msg("agent-vault: closed a SOCKS5 connection the proxy can't handle; it handles only HTTP/1.1 web traffic from clients that trust its CA")
}

// bufferedConn lets the first byte be peeked and then handed on, to tls.Server or to the plain HTTP
// server, without the byte being consumed.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedConn(c net.Conn) *bufferedConn {
	return &bufferedConn{Conn: c, reader: bufio.NewReader(c)}
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.reader.Read(p) }

// The scheme is the tunnel's, not the inner request's, and the target host comes from the CONNECT line so
// an agent cannot address one host through a tunnel to another.
func (ps *proxyServer) serveTunnel(conn net.Conn, t tunnel) {
	listener := newOneShotListener(conn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ps.forwardHTTP(w, r, t)
		}),
		ReadHeaderTimeout: tunnelReadHeaderTimeout,
		ReadTimeout:       tunnelReadTimeout,
		WriteTimeout:      tunnelWriteTimeout,
		IdleTimeout:       tunnelIdleTimeout,
		MaxHeaderBytes:    maxRequestHeaderBytes,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateHijacked || state == http.StateClosed {
				_ = listener.Close()
			}
		},
	}
	_ = srv.Serve(listener)
}

// handlePlainForward serves only http:// absolute-form. https:// is rejected so the proxy can never be
// used to TLS-strip: HTTPS has to arrive as CONNECT.
func (ps *proxyServer) handlePlainForward(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(plainReadTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(plainWriteTimeout))

	if !r.URL.IsAbs() || strings.EqualFold(r.URL.Scheme, "https") {
		http.Error(w, "only absolute-form http:// requests are forwarded; use CONNECT for https", http.StatusBadRequest)
		return
	}

	sessionToken, ok := requestSessionToken(r)
	if !ok {
		writeProxyAuthChallenge(w)
		return
	}

	hostname, port, err := parseForwardTarget(r.URL.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid target %q", r.URL.Host), http.StatusBadRequest)
		return
	}

	if _, err := ps.cache.get(sessionToken); err != nil {
		ps.denyAtGate(w, sessionToken, hostname, port, err)
		return
	}

	ps.forwardHTTP(w, r, tunnel{scheme: "http", hostname: hostname, port: port, sessionToken: sessionToken})
}

func (ps *proxyServer) forwardHTTP(w http.ResponseWriter, r *http.Request, t tunnel) {
	scheme, hostname, port := t.scheme, t.hostname, t.port
	// Before anything reads the path: the policy check, the substitutions and the forward all have to see
	// the bytes the agent sent, not the ones Go rebuilds.
	normalizeRequestTarget(r.URL)

	// requestPath rather than EscapedPath, so a brokered request is never recorded with a blank path.
	reqPath := truncatePath(requestPath(r))
	reqMethod := truncateLogged(r.Method, maxLoggedMethodLen)

	resp, matched, outcome, err := ps.forward(r, t)

	// The body is fixed text per outcome, never err.Error(): an APIError carries the control-plane URL and
	// request id, and a dial error names the upstream address. The detail goes on the log line below.
	// A gone session is 403 with the same words the CONNECT gate uses, so SDKs stop rather than retry.
	decision := decisionPassthrough
	status := 0
	body := ""
	switch {
	case errors.Is(err, errHostBlocked), errors.Is(err, errPolicyBlocked):
		decision, status, body = decisionBlocked, http.StatusForbidden, err.Error()
	case errors.Is(err, errBodyUnreadable):
		// The agent's upload broke, so this is its request to retry rather than an upstream or policy failure.
		decision, status, body = decisionBlocked, http.StatusBadRequest, err.Error()
	case errors.Is(err, errOpaqueTarget):
		decision, status, body = decisionBlocked, http.StatusBadRequest, errOpaqueTarget.Error()
	case errors.Is(err, errPrivateDestination):
		// The dial error names the address it refused, which would tell the agent about the internal network.
		decision, status, body = decisionBlocked, http.StatusForbidden, errPrivateDestination.Error()
	case isProxyTokenRejected(err):
		decision, status, body = decisionError, http.StatusServiceUnavailable, proxyRevokedBody
	case isSessionGone(err):
		decision, status, body = decisionBlocked, http.StatusForbidden, "the session is no longer valid"
	case errors.Is(err, errSessionResolve):
		decision, status, body = decisionError, http.StatusBadGateway, "failed to resolve the session"
	case err != nil:
		decision, status, body = decisionError, http.StatusBadGateway, "failed to reach the upstream"
	case outcome.brokered:
		decision, status = decisionBrokered, resp.StatusCode
	default:
		status = resp.StatusCode
	}

	event := log.Debug()
	switch decision {
	case decisionBrokered:
		event = log.Info()
	case decisionBlocked:
		event = log.Warn()
	case decisionError:
		event = log.Error()
	}
	event.Str("method", reqMethod).
		Str("host", hostname).
		Str("path", reqPath).
		Str("decision", decision).
		Int("status", status)
	if t.viaSocks5 {
		event = event.Str("door", "socks5")
	}
	if matched != nil {
		event = event.Str("service", matched.name).Str("accessBundle", matched.accessBundleName)
	}
	if outcome.brokered && !strings.EqualFold(scheme, "https") {
		event = event.Bool("plaintext", true)
	}
	// The logged path is always the agent's, so without this a substitution that matched nothing reads
	// exactly like one that fired.
	if len(outcome.substituted) > 0 {
		event = event.Strs("substituted", outcome.substituted)
	}
	if err != nil {
		event = event.Err(err)
	}
	event.Msg("agent-vault: request")

	// reqPath was taken before forward, so a credential substituted into the path never reaches the record.
	if outcome.sessionLog != nil {
		var service, bundle, serviceType *string
		if matched != nil {
			kind := toServiceKind(matched.kind)
			service, bundle, serviceType = &matched.name, &matched.accessBundleName, &kind
		}
		ps.sessionLogs.record(outcome.sessionLog, sessionLogRecord{
			Method:       reqMethod,
			Host:         hostname,
			Port:         port,
			Path:         reqPath,
			Status:       status,
			Decision:     decision,
			Service:      service,
			AccessBundle: bundle,
			ServiceType:  serviceType,
			MCP:          outcome.mcp,
		})
	}

	if err != nil {
		http.Error(w, body, status)
		return
	}
	defer resp.Body.Close()

	stripHopByHopHeaders(resp.Header)
	dst := w.Header()
	for name, values := range resp.Header {
		for _, v := range values {
			dst.Add(name, v)
		}
	}
	// The status line is already on the wire, so a failure part way through the body cannot be reported
	// as a status. Returning normally would have net/http finish the chunked encoding and hand the agent
	// a well-formed truncated 200; aborting drops the connection so the agent sees a failure instead.
	// httputil.ReverseProxy does the same for the same reason.
	w.WriteHeader(resp.StatusCode)
	fw := &flushingWriter{ResponseWriter: w, rc: http.NewResponseController(w)}
	if _, copyErr := io.Copy(fw, resp.Body); copyErr != nil {
		// Only the upstream's failure is ours to report. A write error is the agent having stopped
		// reading, which is its own business and what the standard library also stays quiet about. So is
		// a cancelled context: the server cancels it when the agent hangs up, and that can reach the
		// upstream read before the next write to the agent fails.
		if fw.writeErr == nil && !errors.Is(copyErr, context.Canceled) {
			log.Warn().Err(copyErr).Str("host", hostname).Msg("agent-vault: upstream stream failed part way")
		}
		panic(http.ErrAbortHandler)
	}
}

// The one place the block decision lives, so the test that covers exceptions runs what forward runs.
func (cfg ProxyConfig) blocksOffBundle(matched *resolvedService, hostname, port string) bool {
	return matched == nil && cfg.TrafficPolicy == TrafficPolicyBundleHosts && !cfg.isAllowedHost(hostname, port)
}

type forwardOutcome struct {
	brokered    bool
	substituted []string
	sessionLog  *sessionLogGrant
	mcp         *mcpDetail
}

func (ps *proxyServer) forward(req *http.Request, t tunnel) (*http.Response, *resolvedService, forwardOutcome, error) {
	scheme, hostname, port, sessionToken := t.scheme, t.hostname, t.port, t.sessionToken
	var outcome forwardOutcome

	services, grant, err := ps.cache.lookup(sessionToken)
	if err != nil {
		return nil, nil, outcome, fmt.Errorf("%w: %w", errSessionResolve, err)
	}
	outcome.sessionLog = grant

	// TRACE and TRACK make the upstream reflect the injected credential back in the response body. Upper
	// -cased like allowsMethod already was, or a lowercase "trace" walks past. Refused here rather than in
	// the handler so it is logged like every other refusal.
	if method := strings.ToUpper(req.Method); method == http.MethodTrace || method == "TRACK" {
		return nil, nil, outcome, fmt.Errorf("method %s echoes headers back: %w", method, errPolicyBlocked)
	}

	// 'http:admin/secrets' parses to an empty path and a non-empty Opaque, which the upstream would receive
	// as a request-target with no leading slash. handlePlainForward refuses the shape already; the tunnel
	// reaches this handler directly, so the refusal belongs here where both doors meet.
	if req.URL.Opaque != "" {
		return nil, nil, outcome, errOpaqueTarget
	}

	matched := bestMatch(services, hostname, port)
	// One copy for every decision this request makes. A poll can swap the settings at any moment, and a
	// request judged by two different policies could pass the gate under one and skip the private-address
	// check under the other.
	cfg := ps.currentConfig()
	// Set only when the proxy injected a credential Infisical can refresh, which is what decides whether an
	// upstream 401 or 403 is handled here or passed to the agent.
	var sent *credential
	// A credential that cannot be refreshed, injected into an MCP request: an upstream 401 then means the
	// stored credential is wrong, which the agent cannot fix by logging in itself.
	staticMCP := false

	if cfg.blocksOffBundle(matched, hostname, port) {
		return nil, nil, outcome, fmt.Errorf("no service covers host %q: %w", hostname, errHostBlocked)
	}

	if matched != nil {
		if err := checkServicePolicy(matched, req); err != nil {
			return nil, matched, outcome, err
		}
	}

	req.URL.Scheme = scheme
	req.URL.Host = net.JoinHostPort(hostname, port)
	// Pin Host to the matched authority: the inner tunnel's Host header is agent-controlled and Go forwards
	// it verbatim.
	req.Host = hostHeaderForScheme(scheme, req.URL.Host)
	req.RequestURI = ""

	// Stripped before injecting, so a client's Connection header cannot delete the credential.
	stripHopByHopHeaders(req.Header)

	// A service reaches port 443 by default, which everywhere else in the product means TLS, so plain HTTP
	// here is either a tunnel that declined to handshake or an http:// URL naming 443 — nothing legitimate.
	// Refused before substitution, which would otherwise put a secret in the path of a cleartext request.
	if matched != nil && scheme == "http" && port == "443" {
		return nil, matched, outcome, fmt.Errorf(
			"service %q expects TLS on port 443; refusing to broker plain HTTP: %w", matched.name, errPolicyBlocked)
	}
	// Infisical only accepts an https:// URL for an MCP server, so plain HTTP is refused whatever the port: a
	// server on a custom port would otherwise get its token in cleartext.
	if matched != nil && scheme == "http" && matched.kind == serviceKindMCP {
		return nil, matched, outcome, fmt.Errorf(
			"MCP service %q expects TLS; refusing to broker plain HTTP: %w", matched.name, errPolicyBlocked)
	}

	if matched != nil {
		// Before anything is injected, so the names it records can only have come from the agent. Parsed
		// only for a session log; with logs off the body is still buffered for an OAuth credential, so a
		// rejected token's request can be sent again.
		if matched.kind == serviceKindMCP {
			if grant != nil {
				outcome.mcp = inspectMCPRequest(req)
			} else if matched.credential.refreshable {
				bufferMCPRequest(req)
			}
		}

		// Substitutions first, so an injected real value can never itself be rewritten. The credential last,
		// so a custom header naming the credential's own header loses rather than replacing the token.
		substituted, err := applySubstitutions(req, matched.name, matched.substitutions)
		outcome.substituted = substituted
		if err != nil {
			return nil, matched, outcome, err
		}
		brokered, resolvedInHeader := injectCustomHeaders(req, matched.customHeaders, matched.substitutions)
		outcome.brokered = brokered
		if resolvedInHeader && !containsSurface(outcome.substituted, surfaceHeader) {
			outcome.substituted = append(outcome.substituted, surfaceHeader)
		}
		if injectCredential(req, &matched.credential) {
			outcome.brokered = true
			if matched.credential.refreshable {
				sent = &matched.credential
			} else if matched.kind == serviceKindMCP {
				staticMCP = true
			}
		}

		// After the brokered headers rather than before them, so a custom header cannot reintroduce an
		// override of the method the allowlist already judged.
		if matched.allowedMethods != nil {
			stripMethodOverrideHeaders(req.Header)
		}
		if len(outcome.substituted) > 0 {
			outcome.brokered = true
		}

		if len(matched.allowedPathPrefixes) > 0 && containsSurface(outcome.substituted, surfacePath) {
			if !pathAllowedAfterSubstitution(requestPath(req), req.URL.Path, matched.allowedPathPrefixes) {
				// The path now carries the real credential, so it must not reach the body or the log.
				return nil, matched, outcome, fmt.Errorf(
					"service %q does not allow the path this request substitutes to: %w",
					matched.name, errPolicyBlocked,
				)
			}
		}
	}

	// Captured before the round trip, which consumes the body.
	var replay []byte
	replayable := false
	if sent != nil {
		replay, replayable = replayableBody(req)
	}

	upstream, err := ps.upstreamFor(t, matched, cfg)
	if err != nil {
		return nil, matched, outcome, err
	}
	resp, err := upstream.RoundTrip(req)
	if err != nil {
		return nil, matched, outcome, err
	}
	// An insufficient_scope challenge too, or the agent's MCP client would start an authorization of its own
	// whose token the proxy then overwrites with the stored one.
	_, insufficientScope := insufficientScopeChallenge(resp)
	if staticMCP && (resp.StatusCode == http.StatusUnauthorized || insufficientScope) {
		_ = resp.Body.Close()
		log.Warn().Str("service", matched.name).Str("serviceId", matched.id).
			Msg("agent-vault: the MCP server rejected the service's credential")
		return upstreamAuthFailed(req, staticCredentialRejectedBody(matched.name)), matched, outcome, nil
	}
	if sent != nil {
		resp, err = ps.handleUpstreamAuth(upstream, req, resp, matched, sessionToken, sent, replay, replayable)
		if err != nil {
			return nil, matched, outcome, err
		}
	}
	return resp, matched, outcome, nil
}

// upstreamFor picks the transport a request leaves through. A SOCKS5 port is meant to face the internet, so
// under the any-host policy a destination no service names may not be private: only an admin naming a host
// in a bundle makes an internal address reachable that way. Under bundle-hosts every reachable host is
// already named. Exceptions do not count here, because the UI hides them once the policy is any-host.
func (ps *proxyServer) upstreamFor(t tunnel, matched *resolvedService, cfg ProxyConfig) (http.RoundTripper, error) {
	if !t.viaSocks5 || ps.socks5AllowPrivate || matched != nil || cfg.TrafficPolicy != TrafficPolicyAnyHost {
		return ps.transport, nil
	}
	if ps.guardedTransport == nil {
		return nil, errPrivateDestination
	}
	return ps.guardedTransport, nil
}

func containsSurface(surfaces []string, target string) bool {
	for _, surface := range surfaces {
		if surface == target {
			return true
		}
	}
	return false
}

func (cfg ProxyConfig) isAllowedHost(hostname, port string) bool {
	raw := cfg.AllowedHosts
	if raw == "" {
		return false
	}
	for _, pattern := range parseHostPatterns(raw) {
		// A bare entry means the host on any port. The 443 default it inherits from the parser is there to
		// keep a credential off plaintext, and an exception never carries one, so plain http to a host
		// written as a bare name would otherwise stay blocked with nothing saying why.
		if !pattern.portWritten {
			pattern.port = port
		}
		if ok, _ := pattern.match(hostname, port); ok {
			return true
		}
	}
	return false
}

type flushingWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
	// The last write failure, so a copy error can be told apart from the upstream's own. io.Copy reports
	// one error for either side.
	writeErr error
}

func (fw *flushingWriter) Write(p []byte) (int, error) {
	// Before the write, not after: a chunk heading for a slow client must not race a deadline set for the previous one.
	_ = fw.rc.SetWriteDeadline(time.Now().Add(streamIdleTimeout))
	n, err := fw.ResponseWriter.Write(p)
	if err != nil {
		fw.writeErr = err
	}
	if flusher, ok := fw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

// DNS is case-insensitive and a trailing dot names the same host, so normalise once here and use that
// value everywhere downstream.
func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(host), "."))
}

// SplitHostPort is happy with ":443", ":" and "", and an empty host means this machine to the dialer,
// so a target naming no host would reach whatever is listening on the box the proxy runs on.
var errNoHostInTarget = errors.New("the target names no host")

// DNS limits. Every hostname that can resolve fits them; one that does not is either a typo or an attempt
// to grow a leaf certificate, which embeds the name, to the size of the request header cap. IP literals
// have their own grammar and are exempt. Nothing about the characters is checked, so underscores and
// single-label names keep working.
const (
	maxHostnameBytes = 253
	maxLabelBytes    = 63
)

var errHostTooLong = errors.New("the target host is longer than a DNS name can be")

var errBadPort = errors.New("the target port must be a number from 1 to 65535")

func validPort(port string) bool {
	if len(port) == 0 || len(port) > 5 || port[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n <= 65535
}

func checkedTarget(hostname, port string) (string, string, error) {
	// Normalised first: a host of only dots is non-empty until the trailing dots come off.
	hostname = normalizeHostname(hostname)
	if hostname == "" || port == "" {
		return "", "", errNoHostInTarget
	}
	if !validPort(port) {
		return "", "", errBadPort
	}
	if net.ParseIP(hostname) == nil {
		if len(hostname) > maxHostnameBytes {
			return "", "", errHostTooLong
		}
		for _, label := range strings.Split(hostname, ".") {
			if len(label) > maxLabelBytes {
				return "", "", errHostTooLong
			}
		}
	}
	return hostname, port, nil
}

func parseConnectTarget(target string) (hostname, port string, err error) {
	hostname, port, err = net.SplitHostPort(target)
	if err == nil {
		return checkedTarget(hostname, port)
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && strings.Contains(addrErr.Err, "missing port") {
		hostname, port, err = net.SplitHostPort(target + ":443")
		if err != nil {
			return "", "", err
		}
		return checkedTarget(hostname, port)
	}
	return "", "", err
}

func parseForwardTarget(target string) (hostname, port string, err error) {
	hostname, port, err = net.SplitHostPort(target)
	if err == nil {
		return checkedTarget(hostname, port)
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && strings.Contains(addrErr.Err, "missing port") {
		hostname, port, err = net.SplitHostPort(target + ":80")
		if err != nil {
			return "", "", err
		}
		return checkedTarget(hostname, port)
	}
	return "", "", err
}

func hostHeaderForScheme(scheme, target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	var schemeDefault string
	switch strings.ToLower(scheme) {
	case "https":
		schemeDefault = "443"
	case "http":
		schemeDefault = "80"
	default:
		return target
	}
	if port != schemeDefault {
		return target
	}
	// An IPv6 literal keeps its brackets or the header is malformed, and dropping the port is the only
	// path that hands back a bare host. nginx answers 400 to the unbracketed form.
	if strings.ContainsRune(host, ':') {
		return "[" + host + "]"
	}
	return host
}

func parseProxyBasicAuth(header string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64Decode(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	username, password, found := strings.Cut(decoded, ":")
	return username, password, found
}

// serveSelfEndpoint answers the proxy's own endpoints, and only for origin-form requests addressed to
// this proxy. Getting that backwards would let the proxy answer for a host it is proxying.
func (ps *proxyServer) serveSelfEndpoint(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodConnect || r.URL.IsAbs() {
		return false
	}
	if !strings.HasPrefix(r.URL.Path, "/_agent-vault/") {
		return false
	}

	switch r.URL.Path {
	case "/_agent-vault/ca":
		// Unauthenticated: a public certificate is public, and this is how an agent trusts the proxy.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"proxyId":     ps.opts.ProxyID,
			"name":        ps.opts.ProxyName,
			"certificate": string(ps.ca.RootPEM()),
			"fingerprint": ps.ca.Fingerprint(),
		})
		return true

	}

	http.NotFound(w, r)
	return true
}

type oneShotListener struct {
	conn      net.Conn
	yield     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

var errListenerClosed = errors.New("agentvault: one-shot listener closed")

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{conn: c, yield: make(chan net.Conn, 1), closed: make(chan struct{})}
	l.yield <- c
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.yield:
		return c, nil
	case <-l.closed:
		return nil, errListenerClosed
	}
}

func (l *oneShotListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	onFull    func()
	fullOnce  sync.Once
}

func newLimitListener(l net.Listener, n int, onFull func()) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{}), onFull: onFull}
}

// Closing the listener wakes a goroutine parked in Accept but not one parked on the semaphore send, so
// acquisition also watches done, the same shape as x/net's LimitListener.
func (l *limitListener) acquire() bool {
	select {
	case l.sem <- struct{}{}:
		return true
	case <-l.done:
		return false
	default:
	}
	l.fullOnce.Do(l.onFull)
	select {
	case l.sem <- struct{}{}:
		return true
	case <-l.done:
		return false
	}
}

func (l *limitListener) Accept() (net.Conn, error) {
	if !l.acquire() {
		// The listener is closed, so the underlying Accept should fail. If it hands back a connection
		// anyway there is no slot for it, so it is closed and the loop waits for the real error.
		for {
			conn, err := l.Listener.Accept()
			if err != nil {
				return nil, err
			}
			_ = conn.Close()
		}
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: conn, release: func() { <-l.sem }}, nil
}

func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

type limitConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}

func base64Decode(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
