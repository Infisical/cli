package agentvault

import (
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
	"time"

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

	maxLoggedPathLen = 2048
)

var errHostBlocked = errors.New("host blocked by policy")

const (
	decisionBrokered    = "brokered"
	decisionPassthrough = "passthrough"
	decisionBlocked     = "blocked"
	decisionError       = "error"
)

type Options struct {
	Port       int
	DataDir    string
	ProxyToken func() string
	ProxyID    string
	ProxyName  string
}

type proxyServer struct {
	opts      Options
	ca        *caManager
	cache     *sessionCache
	transport http.RoundTripper

	configMu sync.RWMutex
	config   ProxyConfig

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
func (ps *proxyServer) denyAtGate(w http.ResponseWriter, sessionToken, hostname, port string, err error) {
	if isSessionGone(err) {
		log.Warn().
			Str("host", net.JoinHostPort(hostname, port)).
			Str("sessionKey", sessionKey(sessionToken)).
			Str("decision", decisionBlocked).
			Int("status", http.StatusForbidden).
			Msg("agent-vault: refused, the session is no longer valid")
		http.Error(w, "the session is no longer valid", http.StatusForbidden)
		return
	}
	log.Error().
		Err(err).
		Str("host", net.JoinHostPort(hostname, port)).
		Str("sessionKey", sessionKey(sessionToken)).
		Str("decision", decisionError).
		Int("status", http.StatusBadGateway).
		Msg("agent-vault: refused, the session could not be resolved")
	http.Error(w, "failed to resolve the session", http.StatusBadGateway)
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

	// Resolve before the DNS lookup below and the leaf minting further down, so an unauthenticated caller
	// cannot make the proxy work on their behalf.
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

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
		// http/1.1 only. An h2-only client fails ALPN here, which is a documented unsupported case rather than
		// something to paper over with a silent downgrade.
		NextProtos: []string{"http/1.1"},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	ps.serveTunnel(tlsConn, hostname, port, sessionToken)
}

func (ps *proxyServer) serveTunnel(tlsConn *tls.Conn, hostname, port, sessionToken string) {
	listener := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ps.forwardHTTP(w, r, "https", hostname, port, sessionToken)
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

	ps.forwardHTTP(w, r, "http", hostname, port, sessionToken)
}

func (ps *proxyServer) forwardHTTP(w http.ResponseWriter, r *http.Request, scheme, hostname, port, sessionToken string) {
	// TRACE and TRACK make the upstream reflect the injected credential back in the response body.
	if r.Method == http.MethodTrace || r.Method == "TRACK" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reqPath := r.URL.EscapedPath()
	if len(reqPath) > maxLoggedPathLen {
		reqPath = reqPath[:maxLoggedPathLen] + "...[truncated]"
	}

	resp, matched, err := ps.forward(r, scheme, hostname, port, sessionToken)

	decision := decisionPassthrough
	status := 0
	switch {
	case errors.Is(err, errHostBlocked):
		decision, status = decisionBlocked, http.StatusForbidden
	case err != nil:
		decision, status = decisionError, http.StatusBadGateway
	// brokered means a credential went out, not merely that a connection matched.
	case matched != nil && matched.credential.kind != credentialPassthrough:
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
	event.Str("method", r.Method).
		Str("host", hostname).
		Str("path", reqPath).
		Str("decision", decision).
		Int("status", status)
	if matched != nil {
		event = event.Str("connection", matched.name).Str("accessBundle", matched.accessBundleName)
	}
	event.Msg("agent-vault: request")

	if err != nil {
		http.Error(w, err.Error(), status)
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

func (ps *proxyServer) forward(req *http.Request, scheme, hostname, port, sessionToken string) (*http.Response, *resolvedConnection, error) {
	connections, err := ps.cache.get(sessionToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve the session: %w", err)
	}

	matched := bestMatch(connections, hostname, port)

	if matched == nil && ps.currentConfig().UnmatchedHost == UnmatchedDeny && !ps.isBypassed(hostname, port) {
		return nil, nil, fmt.Errorf("no connection covers host %q: %w", hostname, errHostBlocked)
	}

	req.URL.Scheme = scheme
	req.URL.Host = net.JoinHostPort(hostname, port)
	// Pin Host to the matched authority: the inner tunnel's Host header is agent-controlled and Go forwards
	// it verbatim.
	req.Host = hostHeaderForScheme(scheme, req.URL.Host)
	req.RequestURI = ""

	// Stripped before injecting, so a client's Connection header cannot delete the credential.
	stripHopByHopHeaders(req.Header)

	if matched != nil {
		// A credential is only ever injected over TLS, whatever port the pattern names.
		if !strings.EqualFold(scheme, "https") {
			log.Warn().
				Str("host", hostname).
				Str("connection", matched.name).
				Msg("agent-vault: refusing to attach a credential over plaintext http")
			matched = nil
		} else {
			injectCredential(req, &matched.credential)
		}
	}

	resp, err := ps.transport.RoundTrip(req)
	if err != nil {
		return nil, matched, err
	}
	return resp, matched, nil
}

func (ps *proxyServer) isBypassed(hostname, port string) bool {
	raw := ps.currentConfig().BypassHosts
	if raw == "" {
		return false
	}
	for _, pattern := range parseHostPatterns(raw) {
		// A bare entry means the host on any port. The 443 default it inherits from the parser is there to
		// keep a credential off plaintext, and a bypass entry never carries one, so plain http to a host
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
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// SplitHostPort is happy with ":443", ":" and "", and an empty host means this machine to the dialer,
// so a target naming no host would reach a service on the box the proxy runs on.
var errNoHostInTarget = errors.New("the target names no host")

func checkedTarget(hostname, port string) (string, string, error) {
	if hostname == "" || port == "" {
		return "", "", errNoHostInTarget
	}
	return normalizeHostname(hostname), port, nil
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
	sem      chan struct{}
	onFull   func()
	fullOnce sync.Once
}

func newLimitListener(l net.Listener, n int, onFull func()) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), onFull: onFull}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	default:
		l.fullOnce.Do(l.onFull)
		l.sem <- struct{}{}
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: conn, release: func() { <-l.sem }}, nil
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
