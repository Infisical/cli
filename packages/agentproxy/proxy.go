package agentproxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	UnmatchedAllow = "allow"
	UnmatchedBlock = "block"
)

const (
	connectReadTimeout  = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	idleTunnelTimeout   = 5 * time.Minute
	// maxRequestHeaderBytes bounds a single request's header block. http.ReadRequest, unlike
	// http.Server, applies no MaxHeaderBytes, so without this an unauthenticated client could send
	// unbounded headers and exhaust proxy memory. Matches Go's http.DefaultMaxHeaderBytes (1 MB).
	maxRequestHeaderBytes = 1 << 20
)

var (
	errHostBlocked    = errors.New("host blocked by policy")
	errHeaderTooLarge = errors.New("request header exceeds limit")
)

// headerLimitedReader caps bytes read while an HTTP request's headers are parsed, then switches to
// unlimited for the body. Reused across keep-alive requests on the same connection by re-arming the
// limit before each http.ReadRequest.
type headerLimitedReader struct {
	r         io.Reader
	remaining int64
	limited   bool
}

func (h *headerLimitedReader) Read(p []byte) (int, error) {
	if h.limited {
		if h.remaining <= 0 {
			return 0, errHeaderTooLarge
		}
		if int64(len(p)) > h.remaining {
			p = p[:h.remaining]
		}
	}
	n, err := h.r.Read(p)
	if h.limited {
		h.remaining -= int64(n)
	}
	return n, err
}

func (h *headerLimitedReader) armHeaderLimit() { h.remaining = maxRequestHeaderBytes; h.limited = true }
func (h *headerLimitedReader) releaseLimit()   { h.limited = false }

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
	transport *http.Transport
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

func Start(opts Options) error {
	ps := &proxyServer{
		opts:      opts,
		ca:        newCaManager(opts.ProxyToken),
		cache:     newAgentCache(opts.ProxyToken),
		transport: newUpstreamTransport(),
	}

	if err := ps.ca.ensureIntermediate(); err != nil {
		return fmt.Errorf("failed to initialize agent proxy CA: %w", err)
	}

	go ps.pollLoop()

	if addr := portInUse(opts.Port); addr != "" {
		return fmt.Errorf("port %d is already in use (%s); another process is listening. Choose a free port with --port", opts.Port, addr)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", opts.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", opts.Port, err)
	}
	log.Info().Msgf("Infisical agent proxy listening on :%d", opts.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Info().Msg("agent proxy listener closed; shutting down")
				return nil
			}
			log.Warn().Err(err).Msg("failed to accept connection")
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go ps.handleConn(conn)
	}
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

func (ps *proxyServer) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	limited := &headerLimitedReader{r: clientConn}
	reader := bufio.NewReader(limited)
	readTimeout := connectReadTimeout
	for {
		_ = clientConn.SetReadDeadline(time.Now().Add(readTimeout))
		limited.armHeaderLimit()
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, errHeaderTooLarge) {
				writeHTTPError(clientConn, http.StatusRequestHeaderFieldsTooLarge, errHeaderTooLarge.Error())
			}
			return
		}
		limited.releaseLimit()
		_ = clientConn.SetReadDeadline(time.Time{})

		if req.Method == http.MethodConnect {
			ps.handleConnect(clientConn, req)
			return
		}
		if !ps.handlePlainForward(clientConn, req) {
			return
		}
		readTimeout = idleTunnelTimeout
	}
}

func (ps *proxyServer) handleConnect(clientConn net.Conn, req *http.Request) {
	scope, jwt, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok {
		writeProxyAuthRequired(clientConn)
		return
	}

	hostname, port, err := parseConnectTarget(req.Host)
	if err != nil {
		writeProxyResponse(clientConn, http.StatusBadRequest, fmt.Sprintf("invalid CONNECT target %q", req.Host))
		return
	}

	// Authenticate before minting: otherwise any syntactically valid Proxy-Authorization header forces unbounded key generation and leaf-cache growth.
	if _, err := ps.cache.get(jwt, scope); err != nil {
		if isAuthError(err) {
			writeProxyResponse(clientConn, http.StatusForbidden, "proxy authorization failed")
		} else {
			writeProxyResponse(clientConn, http.StatusBadGateway, "failed to resolve agent permissions")
		}
		return
	}

	leaf, err := ps.ca.mintLeaf(hostname)
	if err != nil {
		writeProxyResponse(clientConn, http.StatusInternalServerError, "failed to mint certificate")
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	defer tlsConn.Close()

	ps.serveTunnel(tlsConn, hostname, port, jwt, scope)
}

// Only http:// absolute-form is served; https:// is rejected so the proxy can never be used to silently TLS-strip (HTTPS must arrive as CONNECT).
func (ps *proxyServer) handlePlainForward(clientConn net.Conn, req *http.Request) bool {
	if !strings.EqualFold(req.URL.Scheme, "http") || req.URL.Host == "" {
		writeHTTPError(clientConn, http.StatusBadRequest, "non-CONNECT requests must be absolute-form http:// (use CONNECT for https:// upstreams)")
		return false
	}

	scope, jwt, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok {
		writeProxyAuthRequired(clientConn)
		return false
	}

	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}

	resp, err := ps.forward(req, "http", hostname, port, jwt, scope)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errHostBlocked) {
			status = http.StatusForbidden
		}
		writeHTTPError(clientConn, status, err.Error())
		return false
	}

	if err := resp.Write(clientConn); err != nil {
		resp.Body.Close()
		return false
	}
	resp.Body.Close()
	drainRequestBody(req)

	return !req.Close && !resp.Close
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

func (ps *proxyServer) serveTunnel(tlsConn *tls.Conn, hostname, port, jwt string, scope agentScope) {
	limited := &headerLimitedReader{r: tlsConn}
	tlsReader := bufio.NewReader(limited)

	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(idleTunnelTimeout))
		limited.armHeaderLimit()
		req, err := http.ReadRequest(tlsReader)
		if err != nil {
			if errors.Is(err, errHeaderTooLarge) {
				writeHTTPError(tlsConn, http.StatusRequestHeaderFieldsTooLarge, errHeaderTooLarge.Error())
			} else if !errors.Is(err, io.EOF) {
				log.Debug().Err(err).Msg("tunnel read ended")
			}
			return
		}
		limited.releaseLimit()
		_ = tlsConn.SetReadDeadline(time.Time{})

		resp, err := ps.forward(req, "https", hostname, port, jwt, scope)
		if err != nil {
			if errors.Is(err, errHostBlocked) {
				writeHTTPError(tlsConn, http.StatusForbidden, err.Error())
			} else {
				writeHTTPError(tlsConn, http.StatusBadGateway, err.Error())
			}
			return
		}

		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		drainRequestBody(req)
	}
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
		if err := applyCredentials(req, svc); err != nil {
			return nil, fmt.Errorf("failed to apply credentials: %w", err)
		}
	}

	return ps.transport.RoundTrip(req)
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

func drainRequestBody(req *http.Request) {
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
}

func writeProxyAuthRequired(conn net.Conn) {
	conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")) // #nosec G104
}

func writeProxyResponse(conn net.Conn, status int, msg string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(msg), msg) // #nosec G104
}

func writeHTTPError(conn io.Writer, status int, msg string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(msg), msg) // #nosec G104
}
