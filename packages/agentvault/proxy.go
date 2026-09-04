package agentvault

import (
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
	// The shipped `secrets agent-proxy start` already defaults to 17322 and is not being removed, so a
	// collision here would mean the second of the two to start fails to bind. Phase 4's own verification
	// runs both on one box.
	DefaultPort = 17323

	tlsHandshakeTimeout = 10 * time.Second

	// Outer ingress. No server-level Read/WriteTimeout: they would cut CONNECT hijacks and long streaming
	// responses. Plaintext forwards are bounded per-request instead.
	frontReadHeaderTimeout = 30 * time.Second
	frontIdleTimeout       = 5 * time.Minute

	// Inner per-tunnel server. The write timeouts are absolute deadlines set at request start, so they
	// only bound a response that has produced nothing yet; once bytes flow, flushingWriter replaces them
	// with a rolling idle deadline. Left generous because there is no ResponseHeaderTimeout on the
	// upstream transport, and a slow API is not a stalled one.
	tunnelReadHeaderTimeout = 10 * time.Second
	tunnelReadTimeout       = 60 * time.Second
	tunnelWriteTimeout      = 30 * time.Minute
	tunnelIdleTimeout       = 2 * time.Minute

	plainReadTimeout  = 60 * time.Second
	plainWriteTimeout = 30 * time.Minute

	// Refreshed on every flushed chunk, so a response lives as long as it keeps producing and a stalled
	// one still dies. Without it the absolute write deadline cuts a healthy stream mid-flight at exactly
	// 30 minutes, which is how SSE, MCP and log tails behave.
	streamIdleTimeout = 5 * time.Minute

	maxRequestHeaderBytes = 1 << 20

	// Caps simultaneous client connections so a flood of sockets cannot exhaust file descriptors or
	// goroutines. A live tunnel holds its slot for the tunnel's lifetime.
	maxConcurrentConns = 512

	maxLoggedPathLen = 2048
)

var (
	errHostBlocked    = errors.New("host blocked by policy")
	errPrivateBlocked = errors.New("host is in a blocked private or link-local range")
)

const (
	decisionBrokered    = "brokered"
	decisionPassthrough = "passthrough"
	decisionBlocked     = "blocked"
	decisionError       = "error"
)

// Options is only what the server cannot know: where to bind, where to write, how to log. Traffic policy
// comes from Infisical on every poll, so there is no --unmatched-host or --poll-interval flag.
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

	// The server-owned settings block, swapped wholesale when a heartbeat returns something different.
	configMu sync.RWMutex
	config   ProxyConfig

	// Keeps listener saturation to one warning rather than one per accept.
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
		// Deliberate: an h2 response has no HTTP/1.1 length framing, so re-serializing it into the
		// tunnel would hang the client. h2-only upstreams are a documented unsupported case.
		ForceAttemptHTTP2: false,
	}
}

// requestSessionToken reads the session an agent is running with off Proxy-Authorization. The token is
// the username half of basic auth, which is what an HTTPS_PROXY URL of the form
// http://agv_...@host:port puts there.
func requestSessionToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		return "", false
	}
	username, _, ok := parseProxyBasicAuth(header)
	if !ok || username == "" {
		return "", false
	}
	return username, true
}

func writeProxyAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="Infisical Agent Vault"`)
	http.Error(w, "a session token is required", http.StatusProxyAuthRequired)
}

func (ps *proxyServer) dispatch(w http.ResponseWriter, r *http.Request) {
	// Served before anything else and only for origin-form requests addressed to this proxy, so a
	// proxied request for http://example.com/_agent-vault/ca still reaches example.com untouched.
	if ps.serveSelfEndpoint(w, r) {
		return
	}
	if r.Method == http.MethodConnect {
		ps.handleConnect(w, r)
		return
	}
	ps.handlePlainForward(w, r)
}

func (ps *proxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Everything that can produce an HTTP status happens before Hijack: once hijacked, no status can be
	// sent.
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

	// Resolve before anything that costs the proxy work on the caller's behalf - the DNS lookup below and
	// the leaf minting further down. Otherwise any syntactically valid Proxy-Authorization header can
	// make the proxy resolve arbitrary names and grow its certificate cache.
	if _, err := ps.cache.get(sessionToken); err != nil {
		if isSessionGone(err) {
			http.Error(w, "the session is no longer valid", http.StatusForbidden)
		} else {
			http.Error(w, "failed to resolve the session", http.StatusBadGateway)
		}
		return
	}

	if resolvesToBlockedAddress(hostname) {
		http.Error(w, errPrivateBlocked.Error(), http.StatusForbidden)
		return
	}

	// Every reachable host is treated the same way from here: a certificate is minted and the request is
	// opened, whether it is covered by a connection, allowed by the unmatched-host policy, or named in
	// the bypass list. forward() is where those three part company, and the only difference is whether a
	// credential goes on.

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
		// http/1.1 only. An h2-only client fails ALPN here; that is a documented unsupported case rather
		// than something to paper over with a silent downgrade.
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

// Only http:// absolute-form is served. https:// is rejected so the proxy can never be used to silently
// TLS-strip: HTTPS has to arrive as CONNECT.
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

	// Same ordering as CONNECT: the session resolves before the proxy does a DNS lookup for the caller.
	if _, err := ps.cache.get(sessionToken); err != nil {
		if isSessionGone(err) {
			http.Error(w, "the session is no longer valid", http.StatusForbidden)
		} else {
			http.Error(w, "failed to resolve the session", http.StatusBadGateway)
		}
		return
	}

	if resolvesToBlockedAddress(hostname) {
		http.Error(w, errPrivateBlocked.Error(), http.StatusForbidden)
		return
	}

	ps.forwardHTTP(w, r, "http", hostname, port, sessionToken)
}

func (ps *proxyServer) forwardHTTP(w http.ResponseWriter, r *http.Request, scheme, hostname, port, sessionToken string) {
	// TRACE and TRACK make the upstream reflect the request — including the credential we just injected —
	// back in the response body, which would hand the agent a secret it cannot fetch directly.
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
	case matched != nil:
		decision, status = decisionBrokered, resp.StatusCode
	default:
		status = resp.StatusCode
	}

	event := log.Debug()
	if decision == decisionBlocked {
		event = log.Warn()
	} else if decision == decisionError {
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
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(flushingWriter{ResponseWriter: w, rc: http.NewResponseController(w)}, resp.Body)
}

func (ps *proxyServer) forward(req *http.Request, scheme, hostname, port, sessionToken string) (*http.Response, *resolvedConnection, error) {
	connections, err := ps.cache.get(sessionToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve the session: %w", err)
	}

	matched := bestMatch(connections, hostname, port)

	// The bypass list is a proxy-wide exception to deny, and this is the only thing it does. A host on it
	// is reached the same way as any other: certificate minted, request opened, no credential attached
	// unless a connection covers it. It saves naming every such host as a pass-through connection in a
	// bundle, and it is set by whoever runs the proxy rather than whoever owns the bundle.
	if matched == nil && ps.currentConfig().UnmatchedHost == UnmatchedDeny && !ps.isBypassed(hostname, port) {
		return nil, nil, fmt.Errorf("no connection covers host %q: %w", hostname, errHostBlocked)
	}

	req.URL.Scheme = scheme
	req.URL.Host = net.JoinHostPort(hostname, port)
	// Pin Host to the matched authority: the inner tunnel's Host header is agent-controlled and Go
	// forwards it verbatim, which would let a matched CONNECT deliver the credential to another vhost.
	req.Host = hostHeaderForScheme(scheme, req.URL.Host)
	req.RequestURI = ""

	// Stripped before injecting, so a client's Connection header cannot delete the credential we are
	// about to add. The injected value always wins.
	stripHopByHopHeaders(req.Header)

	if matched != nil {
		// A credential is only ever injected over TLS. The pattern grammar defaults a portless pattern to
		// 443, but an explicit :80 is legal for an internal API, so the port alone is not the check — the
		// scheme is.
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
		if ok, _ := pattern.match(hostname, port); ok {
			return true
		}
	}
	return false
}

type flushingWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (fw flushingWriter) Write(p []byte) (int, error) {
	// Before the write, not after: a chunk that takes a while to reach a slow client must not be racing a
	// deadline set for the previous one.
	_ = fw.rc.SetWriteDeadline(time.Now().Add(streamIdleTimeout))
	n, err := fw.ResponseWriter.Write(p)
	if flusher, ok := fw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func parseConnectTarget(target string) (hostname, port string, err error) {
	hostname, port, err = net.SplitHostPort(target)
	if err == nil {
		return hostname, port, nil
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && strings.Contains(addrErr.Err, "missing port") {
		return net.SplitHostPort(target + ":443")
	}
	return "", "", err
}

func parseForwardTarget(target string) (hostname, port string, err error) {
	hostname, port, err = net.SplitHostPort(target)
	if err == nil {
		return hostname, port, nil
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && strings.Contains(addrErr.Err, "missing port") {
		return net.SplitHostPort(target + ":80")
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
// this proxy. Getting that backwards would let the proxy shadow /_agent-vault/* on every host an agent
// reaches — and §4.1 makes /ca load-bearing for trust, so the rule matters more, not less.
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

	case "/_agent-vault/whoami":
		ps.serveWhoami(w, r)
		return true
	}

	http.NotFound(w, r)
	return true
}

// serveWhoami answers "what can this session actually reach". With no request stream in v1 this is the
// only way an operator gets that answer without reading the proxy's stdout. Host patterns and access
// bundle names only — never a credential value.
func (ps *proxyServer) serveWhoami(w http.ResponseWriter, r *http.Request) {
	sessionToken := r.Header.Get("X-Infisical-Agent-Session")
	if sessionToken == "" {
		sessionToken, _ = requestSessionToken(r)
	}
	if sessionToken == "" {
		http.Error(w, "a session token is required", http.StatusUnauthorized)
		return
	}

	connections, err := ps.cache.get(sessionToken)
	if err != nil {
		if isSessionGone(err) {
			http.Error(w, "the session is no longer valid", http.StatusForbidden)
			return
		}
		http.Error(w, "failed to resolve the session", http.StatusBadGateway)
		return
	}

	type reachable struct {
		Connection   string   `json:"connection"`
		AccessBundle string   `json:"accessBundle"`
		Hosts        []string `json:"hosts"`
		Credential   string   `json:"credentialType"`
	}

	config := ps.currentConfig()
	out := struct {
		ProxyID       string      `json:"proxyId"`
		ProxyName     string      `json:"name"`
		UnmatchedHost string      `json:"unmatchedHost"`
		BypassHosts   string      `json:"bypassHosts"`
		Reachable     []reachable `json:"reachable"`
	}{
		ProxyID:       ps.opts.ProxyID,
		ProxyName:     ps.opts.ProxyName,
		UnmatchedHost: config.UnmatchedHost,
		BypassHosts:   config.BypassHosts,
		Reachable:     make([]reachable, 0, len(connections)),
	}

	for _, conn := range connections {
		hosts := make([]string, 0, len(conn.hostPatterns))
		for _, pattern := range conn.hostPatterns {
			hosts = append(hosts, net.JoinHostPort(pattern.host, pattern.port))
		}
		out.Reachable = append(out.Reachable, reachable{
			Connection:   conn.name,
			AccessBundle: conn.accessBundleName,
			Hosts:        hosts,
			Credential:   conn.credential.kind,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
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

// limitListener caps concurrent connections. Accept blocks once the limit is reached, and a slot frees
// only when a served connection closes. The original blocked silently here, so the agent just hung.
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
