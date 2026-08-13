package agentproxy

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
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

	leaseRevokeShutdownTimeout = 5 * time.Second

	// usageReportTimeout bounds each best-effort "last used" report to the backend.
	usageReportTimeout = 5 * time.Second
)

var errHostBlocked = errors.New("host blocked by policy")

const (
	decisionBrokered    = "brokered"
	decisionPassthrough = "passthrough"
	// A host that no service matches but the agent gateway's allow list permits. Distinct from passthrough so
	// a recording shows that somebody decided this host was fine, rather than that nothing was configured.
	decisionAllowlisted = "allowlisted"
	decisionBlocked     = "blocked"
	decisionError       = "error"
	decisionCanceled    = "canceled"

	activityEventName = "agent-gateway.request"

	maxLoggedPathLen = 2048
)

type Options struct {
	UnmatchedHost string
	// The credential used to fetch resolved bundles: a gateway access token in the gateway, or the caller's
	// own token in local mode.
	ProxyToken func() string

	// AllowedHosts pass through with no credential even under UnmatchedBlock (run --allow-host).
	AllowedHosts []string

	// ProxySecret, when set, must be presented by the client in Proxy-Authorization. Local mode sets it so a
	// loopback listener is not an open credential-injection service for every other process on the machine;
	// remote mode leaves it empty, because there the client is authenticated by mTLS before it reaches here.
	ProxySecret string
}

// sessionResolver hands the server the services a session may broker. One implementation in production
// (bundleResolver, which fetches and caches resolved bundles); tests substitute a static one.
type sessionResolver interface {
	services(session Session) ([]*resolvedService, error)
}

type proxyServer struct {
	opts      Options
	ca        *caManager
	transport http.RoundTripper

	// The session this server brokers for. In the gateway it comes from the mTLS certificate the connection
	// presented, so it is authoritative and is never read from a request; in local mode the CLI holds one.
	session *Session
	bundles sessionResolver

	// Behind a pointer so a Broker can take a cheap per-session view of this server without copying a lock:
	// every session shares one usage tracker, which is what dedupes reports across them.
	usageTracker *usageTracker
	// The session recording. Shared for the same reason, and keyed by session inside.
	recorder *recorder
}

// usageTracker holds the proxied-service ids brokered since the last flush, per session. Keyed by session
// because "last used" is reported through the session that brokered it, and one broker serves many.
type usageTracker struct {
	mu       sync.Mutex
	sessions map[string]map[string]struct{}
	flushing atomic.Bool
	// warnOnce keeps a rejected usage report to one warning per broker, not one per poll.
	warnOnce sync.Once
}

func newUsageTracker() *usageTracker {
	return &usageTracker{sessions: make(map[string]map[string]struct{})}
}

// A server built without a tracker simply does not report usage. Both real construction paths always set
// one; this keeps a bare proxyServer value usable, which the tests rely on, without making usage reporting a
// required dependency of forwarding a request.
func (ps *proxyServer) recordUsage(serviceID string) {
	if ps.usageTracker == nil || ps.session == nil {
		return
	}
	ps.usageTracker.mu.Lock()
	defer ps.usageTracker.mu.Unlock()
	if ps.usageTracker.sessions == nil {
		ps.usageTracker.sessions = make(map[string]map[string]struct{})
	}
	if ps.usageTracker.sessions[ps.session.ID] == nil {
		ps.usageTracker.sessions[ps.session.ID] = make(map[string]struct{})
	}
	ps.usageTracker.sessions[ps.session.ID][serviceID] = struct{}{}
}

// flush reports each session's brokered services through that session. Best effort: a failed batch is
// dropped rather than retried, because a "last used" timestamp is not worth holding memory for.
func (t *usageTracker) flush(token func() string) {
	if t == nil || token == nil {
		return
	}
	if !t.flushing.CompareAndSwap(false, true) {
		return
	}
	defer t.flushing.Store(false)

	t.mu.Lock()
	if len(t.sessions) == 0 {
		t.mu.Unlock()
		return
	}
	snapshot := t.sessions
	t.sessions = make(map[string]map[string]struct{})
	t.mu.Unlock()

	client := resty.New().SetAuthToken(token()).SetTimeout(usageReportTimeout)
	for sessionID, serviceIDs := range snapshot {
		ids := make([]string, 0, len(serviceIDs))
		for serviceID := range serviceIDs {
			ids = append(ids, serviceID)
		}
		if err := api.CallReportAgentGatewayUsage(client, sessionID, ids); err != nil {
			// Warn once: the usual cause is a session that has ended, which fails every attempt.
			t.warnOnce.Do(func() {
				log.Warn().Err(err).Msg("cannot report proxied-service usage, so the services' last-used times will not update")
			})
			log.Debug().Err(err).Msgf("failed to report proxied service usage; dropping batch [sessionId=%s]", sessionID)
		}
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

// requestAuthorized guards the listener itself, not the credentials: which session a connection belongs to
// is decided before this server sees it. Only local mode sets a secret; see Options.ProxySecret.
func (ps *proxyServer) requestAuthorized(r *http.Request) bool {
	if ps.opts.ProxySecret == "" {
		return true
	}
	presented, ok := parseProxySecret(r.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(ps.opts.ProxySecret)) == 1
}

// The services this connection's session may broker. Fetched and cached by the resolver, which fails closed
// once the session stops being valid.
func (ps *proxyServer) resolveServices() ([]*resolvedService, error) {
	if ps.session == nil || ps.bundles == nil {
		return nil, fmt.Errorf("this broker has no session, so there is nothing to broker")
	}
	return ps.bundles.services(*ps.session)
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
	if !ps.requestAuthorized(r) {
		writeProxyAuthChallenge(w)
		return
	}

	hostname, port, err := parseConnectTarget(r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid CONNECT target %q", r.Host), http.StatusBadRequest)
		return
	}

	// Authenticate before minting: otherwise any syntactically valid Proxy-Authorization header forces unbounded key generation and leaf-cache growth.
	if _, err := ps.resolveServices(); err != nil {
		if errors.Is(err, ErrSessionRevoked) {
			http.Error(w, "this brokering session is no longer valid", http.StatusForbidden)
		} else {
			http.Error(w, "failed to resolve the credentials for this session", http.StatusBadGateway)
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

	ps.serveTunnel(tlsConn, hostname, port)
}

// serveTunnel serves HTTP/1.1 requests off the decrypted MITM connection using a fresh http.Server over a
// one-shot listener, so the tunnel gets the same header/timeout enforcement as the ingress.
func (ps *proxyServer) serveTunnel(tlsConn *tls.Conn, hostname, port string) {
	listener := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ps.forwardHTTP(w, r, "https", hostname, port)
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

	if !ps.requestAuthorized(r) {
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

	ps.forwardHTTP(w, r, "http", hostname, port)
}

// forwardHTTP resolves the upstream response and relays it to the client via the ResponseWriter.
func (ps *proxyServer) forwardHTTP(w http.ResponseWriter, r *http.Request, scheme, hostname, port string) {
	// Reject request-echo methods: TRACE/TRACK make the upstream reflect the request (including the injected
	// credential) back in the response body, which would let the agent read a secret it can't fetch directly.
	if r.Method == http.MethodTrace || r.Method == "TRACK" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// EscapedPath keeps the path encoded (no log injection); the cap bounds record size.
	method := r.Method
	reqPath := r.URL.EscapedPath()
	if len(reqPath) > maxLoggedPathLen {
		reqPath = reqPath[:maxLoggedPathLen] + "...[truncated]"
	}

	resp, outcome, err := ps.forward(r, scheme, hostname, port)

	canceled := err != nil && r.Context().Err() != nil

	status := http.StatusOK
	decision := decisionPassthrough
	// Blocked and brokered are checked before canceled, so hanging up cannot drop them from the log.
	switch {
	case errors.Is(err, errHostBlocked):
		decision, status = decisionBlocked, http.StatusForbidden
	case canceled && outcome.service != nil:
		decision, status = decisionBrokered, 0
		ps.recordUsage(outcome.service.id)
	case canceled:
		decision, status = decisionCanceled, 0
	case err != nil:
		decision, status = decisionError, http.StatusBadGateway
	case outcome.service != nil:
		decision, status = decisionBrokered, resp.StatusCode
		ps.recordUsage(outcome.service.id)
	case outcome.allowlisted:
		decision, status = decisionAllowlisted, resp.StatusCode
	default:
		decision, status = decisionPassthrough, resp.StatusCode
	}
	ps.emitActivity(method, reqPath, hostname, port, decision, status, outcome, err)
	ps.recordRequest(method, reqPath, hostname, port, decision, status, outcome, err)

	if err != nil {
		if !canceled {
			http.Error(w, err.Error(), status)
		}
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

// recordRequest is the recording's single entry point, taking the same arguments as the activity log so the
// two can never describe a request differently.
func (ps *proxyServer) recordRequest(
	method, reqPath, hostname, port, decision string,
	status int,
	outcome forwardOutcome,
	cause error,
) {
	if ps.recorder == nil || ps.session == nil {
		return
	}

	portNum, _ := strconv.Atoi(port)

	request := api.AgentGatewaySessionRequest{
		OccurredAt: time.Now().UTC(),
		Method:     method,
		Host:       hostname,
		Port:       portNum,
		Path:       reqPath,
		Decision:   decision,
		StatusCode: status,
	}
	if outcome.service != nil {
		request.ServiceID = outcome.service.id
		request.ServiceName = outcome.service.name
	}
	for _, applied := range outcome.applied {
		request.Credentials = append(request.Credentials, api.AgentGatewaySessionRequestCredential{
			Key:                applied.Key,
			DynamicSecretName:  applied.DynamicSecretName,
			DynamicSecretField: applied.DynamicSecretField,
			Role:               applied.Role,
			Header:             applied.Header,
			Surfaces:           applied.Surfaces,
		})
	}
	if cause != nil {
		request.ErrorMessage = cause.Error()
	}

	if ps.recorder.record(ps.session.ID, request) {
		go ps.recorder.flush()
	}
}

func levelFor(decision string) zerolog.Level {
	switch decision {
	case decisionBlocked:
		return zerolog.WarnLevel
	case decisionError:
		return zerolog.ErrorLevel
	case decisionPassthrough, decisionCanceled:
		return zerolog.DebugLevel
	case decisionAllowlisted:
		return zerolog.InfoLevel
	default:
		return zerolog.InfoLevel
	}
}

func (ps *proxyServer) emitActivity(method, reqPath, hostname, port, decision string, status int, outcome forwardOutcome, cause error) {
	portNum, _ := strconv.Atoi(port)

	ev := log.WithLevel(levelFor(decision)).
		Str("event", activityEventName).
		Str("decision", decision).
		Str("method", method).
		Str("host", hostname).
		Int("port", portNum).
		Str("path", reqPath)
	// The session is what attributes a request, and it came from the certificate (or, locally, from the run
	// itself), so nothing the agent sends can change who a record names.
	if ps.session != nil {
		ev = ev.Str("agentGateway", ps.session.AgentGatewayName).Str("sessionId", ps.session.ID)
		if ps.session.ActorName != "" {
			ev = ev.Str("actorName", ps.session.ActorName)
		}
	}
	if status != 0 {
		ev = ev.Int("status", status)
	}
	if outcome.service != nil {
		ev = ev.Str("serviceId", outcome.service.id).Str("serviceName", outcome.service.name)
	}
	if len(outcome.applied) > 0 {
		ev = ev.Interface("credentials", outcome.applied)
	}
	if cause != nil {
		ev = ev.Err(cause)
	}
	ev.Msg("agent request")
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

type forwardOutcome struct {
	service *resolvedService
	applied []AppliedCredential
	// Set when the request only got through because the host is on the agent gateway's allow list.
	allowlisted bool
}

func (ps *proxyServer) forward(req *http.Request, scheme, hostname, port string) (*http.Response, forwardOutcome, error) {
	services, err := ps.resolveServices()
	if err != nil {
		return nil, forwardOutcome{}, fmt.Errorf("failed to resolve this session's credentials: %w", err)
	}

	outcome := forwardOutcome{}

	svc := bestMatch(services, hostname, port, req.URL.Path)

	if svc == nil && ps.opts.UnmatchedHost == UnmatchedBlock {
		if !ps.hostAllowlisted(hostname) {
			return nil, outcome, fmt.Errorf("host %q has no matching proxied service: %w", hostname, errHostBlocked)
		}
		outcome.allowlisted = true
	}

	outcome.service = svc

	req.URL.Scheme = scheme
	req.URL.Host = net.JoinHostPort(hostname, port)
	// Pin Host to the matched authority: the inner tunnel Host is agent-controlled and Go forwards it verbatim, which would let a matched CONNECT deliver the credential to a different vhost.
	req.Host = hostHeaderForScheme(scheme, req.URL.Host)
	req.RequestURI = ""

	// Strip hop-by-hop before injecting so a client's Connection header cannot delete the injected credential (injected always wins).
	stripHopByHopHeaders(req.Header)

	if svc != nil {
		applied, err := applyCredentials(req, svc.credentials)
		if err != nil {
			return nil, outcome, fmt.Errorf("failed to apply credentials: %w", err)
		}
		outcome.applied = applied
	}

	resp, err := ps.transport.RoundTrip(req)
	if err != nil {
		return nil, outcome, err
	}
	return resp, outcome, nil
}

// hostAllowlisted reports whether hostname is in AllowedHosts (case-insensitive).
func (ps *proxyServer) hostAllowlisted(hostname string) bool {
	for _, h := range ps.opts.AllowedHosts {
		if strings.EqualFold(h, hostname) {
			return true
		}
	}
	return false
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

// parseProxySecret pulls the password half out of a Basic Proxy-Authorization header. The username is
// ignored: the only thing being checked is that the caller knows this run's secret.
func parseProxySecret(header string) (string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", false
	}
	userinfo := string(decoded)
	colon := strings.Index(userinfo, ":")
	if colon == -1 {
		return "", false
	}
	secret := userinfo[colon+1:]
	if secret == "" {
		return "", false
	}
	return secret, true
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
