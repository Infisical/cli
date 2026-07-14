package agentproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	UnmatchedAllow = "allow"
	UnmatchedBlock = "block"
)

const (
	tlsHandshakeTimeout = 10 * time.Second

	// Outer ingress server. No server-level ReadTimeout/WriteTimeout (they'd cut CONNECT hijacks and long
	// streaming responses); plaintext forward requests are bounded per-request instead (handlePlainForward).
	frontReadHeaderTimeout = 30 * time.Second
	frontIdleTimeout       = 5 * time.Minute

	// Inner per-tunnel server. WriteTimeout is roomy for streaming (e.g. large downloads); the read/idle
	// timeouts bound slow-loris and pinned connections now that deadlines aren't hand-managed.
	tunnelReadHeaderTimeout = 10 * time.Second
	tunnelReadTimeout       = 60 * time.Second
	tunnelWriteTimeout      = 30 * time.Minute
	tunnelIdleTimeout       = 2 * time.Minute

	// Plaintext (non-CONNECT) forward requests are bounded per-request via ResponseController deadlines,
	// since the front server sets no ReadTimeout/WriteTimeout.
	plainReadTimeout  = 60 * time.Second
	plainWriteTimeout = 30 * time.Minute

	// maxRequestHeaderBytes bounds a single request's header block via http.Server.MaxHeaderBytes, so an
	// unauthenticated client can't send unbounded headers and exhaust proxy memory. Matches Go's
	// http.DefaultMaxHeaderBytes (1 MB).
	maxRequestHeaderBytes = 1 << 20

	// maxConcurrentConns caps simultaneous client connections so a flood of sockets can't exhaust file
	// descriptors or goroutines. A live tunnel holds its slot for the tunnel's lifetime.
	maxConcurrentConns = 512

	// bound for best-effort lease revocation on shutdown before falling back to server-side expiry
	leaseRevokeShutdownTimeout = 5 * time.Second
)

var errHostBlocked = errors.New("host blocked by policy")

type Options struct {
	Port          int
	UnmatchedHost string
	PollInterval  time.Duration
	ProxyToken    func() string
}

type proxyServer struct {
	opts      Options
	ca        *caManager
	cache     *agentCache
	leases    *leaseStore
	transport http.RoundTripper
}

func newProxyServer(opts Options) *proxyServer {
	leases := newLeaseStore(opts.ProxyToken)
	return &proxyServer{
		opts:      opts,
		ca:        newCaManager(opts.ProxyToken),
		cache:     newAgentCache(opts.ProxyToken, leases),
		leases:    leases,
		transport: newUpstreamTransport(),
	}
}

// Forces HTTP/1.1: h2 responses have no HTTP/1.1 length framing and would hang the re-serialized MITM tunnel; a non-nil empty TLSNextProto is what actually disables h2.
func newUpstreamTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// newFrontServer builds the ingress http.Server. Shared by Start and the test harness so timeout and
// MaxHeaderBytes settings can't drift between them.
func (ps *proxyServer) newFrontServer() *http.Server {
	return &http.Server{
		Handler:           http.HandlerFunc(ps.dispatch),
		ReadHeaderTimeout: frontReadHeaderTimeout,
		IdleTimeout:       frontIdleTimeout,
		MaxHeaderBytes:    maxRequestHeaderBytes,
	}
}

func Start(opts Options) error {
	ps := newProxyServer(opts)

	if err := ps.ca.ensureIntermediate(); err != nil {
		return fmt.Errorf("failed to initialize agent proxy CA: %w", err)
	}

	go ps.pollLoop()

	leaseStop := make(chan struct{})
	go ps.leases.refreshLoop(leaseStop, opts.PollInterval, ps.cache.activeJWTs)

	if addr := portInUse(opts.Port); addr != "" {
		return fmt.Errorf("port %d is already in use (%s); another process is listening. Choose a free port with --port", opts.Port, addr)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", opts.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", opts.Port, err)
	}
	log.Info().Msgf("Infisical agent proxy listening on :%d", opts.Port)

	srv := ps.newFrontServer()

	// Best-effort lease cleanup on shutdown. The server's per-lease scheduled revocation is the backstop,
	// so a missed revoke here just means the lease lives out its TTL.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info().Msg("shutting down agent proxy; revoking active leases")
		close(leaseStop)
		ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeShutdownTimeout)
		defer cancel()
		ps.leases.revokeAll(ctx)
		_ = srv.Shutdown(ctx)
	}()

	err = srv.Serve(newLimitListener(listener, maxConcurrentConns))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func portInUse(port int) string {
	for _, addr := range []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("[::1]:%d", port)} {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr
		}
	}
	return ""
}

func (ps *proxyServer) pollLoop() {
	interval := ps.opts.PollInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		ps.cache.refreshActive()
	}
}

func (ps *proxyServer) dispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		ps.handleConnect(w, r)
		return
	}
	ps.handlePlainForward(w, r)
}

func (ps *proxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	// All authentication and HTTP error responses happen before Hijack: once hijacked, no HTTP status can be sent.
	scope, jwt, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if !ok {
		writeProxyAuthChallenge(w)
		return
	}

	hostname, port, err := parseConnectTarget(r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid CONNECT target %q", r.Host), http.StatusBadRequest)
		return
	}

	// Authenticate before minting: otherwise any syntactically valid Proxy-Authorization header forces unbounded key generation and leaf-cache growth.
	if _, err := ps.cache.get(jwt, scope); err != nil {
		if isAuthError(err) {
			http.Error(w, "proxy authorization failed", http.StatusForbidden)
		} else {
			http.Error(w, "failed to resolve agent permissions", http.StatusBadGateway)
		}
		return
	}

	leaf, err := ps.ca.mintLeaf(hostname)
	if err != nil {
		http.Error(w, "failed to mint certificate", http.StatusInternalServerError)
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
		NextProtos:   []string{"http/1.1"},
	})
	// The handshake runs on the hijacked conn before the inner server, so no server timeout covers it.
	_ = tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	ps.serveTunnel(tlsConn, hostname, port, jwt, scope)
}

// serveTunnel serves HTTP/1.1 requests off the decrypted MITM connection using a fresh http.Server over a
// one-shot listener, so the tunnel gets the same header/timeout enforcement as the ingress.
func (ps *proxyServer) serveTunnel(tlsConn *tls.Conn, hostname, port, jwt string, scope agentScope) {
	listener := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ps.forwardHTTP(w, r, "https", hostname, port, jwt, scope)
		}),
		ReadHeaderTimeout: tunnelReadHeaderTimeout,
		ReadTimeout:       tunnelReadTimeout,
		WriteTimeout:      tunnelWriteTimeout,
		IdleTimeout:       tunnelIdleTimeout,
		MaxHeaderBytes:    maxRequestHeaderBytes,
		// The one-shot listener yields the single conn once, then blocks; closing it on terminal conn state
		// makes Serve return. The conn is owned by http.Server (Closed) or the hijack handler, not closed here.
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateHijacked || state == http.StateClosed {
				_ = listener.Close()
			}
		},
	}
	_ = srv.Serve(listener)
}

// Only http:// absolute-form is served; https:// is rejected so the proxy can never be used to silently TLS-strip (HTTPS must arrive as CONNECT).
func (ps *proxyServer) handlePlainForward(w http.ResponseWriter, r *http.Request) {
	// Bound this request's lifetime: the front server has no ReadTimeout/WriteTimeout (those would cut
	// CONNECT tunnels), so without this a slow body or slow-reading client could pin a connection slot.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(plainReadTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(plainWriteTimeout))

	if !strings.EqualFold(r.URL.Scheme, "http") || r.URL.Host == "" {
		http.Error(w, "non-CONNECT requests must be absolute-form http:// (use CONNECT for https:// upstreams)", http.StatusBadRequest)
		return
	}

	scope, jwt, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if !ok {
		writeProxyAuthChallenge(w)
		return
	}

	hostname := r.URL.Hostname()
	port := r.URL.Port()
	if port == "" {
		port = "80"
	}
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	ps.forwardHTTP(w, r, "http", hostname, port, jwt, scope)
}

// forwardHTTP resolves the upstream response and relays it to the client via the ResponseWriter.
func (ps *proxyServer) forwardHTTP(w http.ResponseWriter, r *http.Request, scheme, hostname, port, jwt string, scope agentScope) {
	// Reject request-echo methods: TRACE/TRACK make the upstream reflect the request (including the injected
	// credential) back in the response body, which would let the agent read a secret it can't fetch directly.
	if r.Method == http.MethodTrace || r.Method == "TRACK" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, err := ps.forward(r, scheme, hostname, port, jwt, scope)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errHostBlocked) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer resp.Body.Close()

	// Strip hop-by-hop response headers (Connection, Transfer-Encoding, etc.) before copying: resp.Write
	// used to frame these itself, but the ResponseWriter owns framing now and would double-frame otherwise.
	// Set-Cookie and Content-Length are deliberately preserved.
	stripHopByHopHeaders(resp.Header)
	dst := w.Header()
	for name, values := range resp.Header {
		for _, v := range values {
			dst.Add(name, v)
		}
	}
	// Relaying via ResponseWriter (rather than the old byte-transparent resp.Write) means Go adds a Date
	// header and, when the upstream omitted Content-Type, sniffs one. Accepted as standard proxy behavior.
	w.WriteHeader(resp.StatusCode)
	// Flush per chunk so streamed responses (e.g. SSE) reach the client instead of buffering.
	_, _ = io.Copy(flushingWriter{w}, resp.Body)
}

// flushingWriter flushes the underlying ResponseWriter after every write so streamed bodies aren't buffered.
type flushingWriter struct{ w http.ResponseWriter }

func (fw flushingWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
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

func (ps *proxyServer) forward(req *http.Request, scheme, hostname, port, jwt string, scope agentScope) (*http.Response, error) {
	services, err := ps.cache.get(jwt, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve agent permissions: %w", err)
	}

	svc := bestMatch(services, hostname, port, req.URL.Path)

	if svc == nil && ps.opts.UnmatchedHost == UnmatchedBlock {
		return nil, fmt.Errorf("host %q has no matching proxied service: %w", hostname, errHostBlocked)
	}

	req.URL.Scheme = scheme
	req.URL.Host = net.JoinHostPort(hostname, port)
	// Pin Host to the matched authority: the inner tunnel Host is agent-controlled and Go forwards it verbatim, which would let a matched CONNECT deliver the credential to a different vhost.
	req.Host = hostHeaderForScheme(scheme, req.URL.Host)
	req.RequestURI = ""

	// Strip hop-by-hop before injecting so a client's Connection header cannot delete the injected credential (injected always wins).
	stripHopByHopHeaders(req.Header)

	if svc != nil {
		creds := ps.materializeCredentials(svc)
		if err := applyCredentials(req, creds); err != nil {
			return nil, fmt.Errorf("failed to apply credentials: %w", err)
		}
	}

	return ps.transport.RoundTrip(req)
}

// materializeCredentials returns a per-request copy of the service's credentials with dynamic-secret values
// resolved from the lease store (minting lazily). A dynamic credential with no available lease value is
// dropped (fail-open, like a missing static secret).
func (ps *proxyServer) materializeCredentials(svc *resolvedService) []resolvedCredential {
	creds := make([]resolvedCredential, 0, len(svc.credentials))
	for _, cred := range svc.credentials {
		if cred.dynamic == nil {
			creds = append(creds, cred)
			continue
		}
		value, ok := ps.leases.value(cred.dynamic.key, cred.dynamic.field)
		if !ok {
			log.Warn().Msgf("proxied service %q: no valid lease value for dynamic secret %q field %q; skipping credential", svc.name, cred.dynamic.key.secretName, cred.dynamic.field)
			continue
		}
		cred.value = value
		creds = append(creds, cred)
	}
	return creds
}

func hostHeaderForScheme(scheme, target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	var defaultPort string
	switch strings.ToLower(scheme) {
	case "https":
		defaultPort = "443"
	case "http":
		defaultPort = "80"
	default:
		return target
	}
	if port != defaultPort {
		return target
	}
	if strings.ContainsRune(host, ':') {
		return "[" + host + "]"
	}
	return host
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func stripHopByHopHeaders(h http.Header) {
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			h.Del(name)
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func parseProxyAuth(header string) (agentScope, string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return agentScope{}, "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return agentScope{}, "", false
	}

	userinfo := string(decoded)
	firstColon := strings.Index(userinfo, ":")
	if firstColon == -1 {
		return agentScope{}, "", false
	}
	projectID := userinfo[:firstColon]
	password := userinfo[firstColon+1:]

	lastColon := strings.LastIndex(password, ":")
	if lastColon == -1 {
		return agentScope{}, "", false
	}
	scopeStr := password[:lastColon]
	jwt := password[lastColon+1:]

	slash := strings.Index(scopeStr, "/")
	var environment, secretPath string
	if slash == -1 {
		environment = scopeStr
		secretPath = "/"
	} else {
		environment = scopeStr[:slash]
		secretPath = scopeStr[slash:]
	}

	if projectID == "" || environment == "" || jwt == "" {
		return agentScope{}, "", false
	}

	return agentScope{projectID: projectID, environment: environment, secretPath: secretPath}, jwt, true
}

func writeProxyAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic")
	http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
}

// oneShotListener adapts a single already-accepted connection into a net.Listener so http.Server can serve
// HTTP/1.1 (incl. keep-alive) off it. The first Accept yields the conn; later Accepts block until Close.
type oneShotListener struct {
	conn      net.Conn
	yield     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

var errListenerClosed = errors.New("agentproxy: one-shot listener closed")

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

// limitListener caps the number of concurrent connections. Accept blocks once the limit is reached and a
// slot frees only when a served connection is closed, so a burst of sockets can't exhaust fds/goroutines.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
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
