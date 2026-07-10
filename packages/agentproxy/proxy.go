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
	connectReadTimeout  = 30 * time.Second // time allowed to send the CONNECT request
	tlsHandshakeTimeout = 10 * time.Second // time allowed to complete the MITM TLS handshake
	idleTunnelTimeout   = 5 * time.Minute  // max idle time waiting for the next request on a tunnel
)

// errHostBlocked marks a request rejected by the unmatched-host=block policy so it maps to 403.
var errHostBlocked = errors.New("host blocked by policy")

type Options struct {
	Port          int
	UnmatchedHost string        // allow | block
	PollInterval  time.Duration // cache refresh cadence
	ProxyToken    func() string // returns the agent proxy MI's current access token (refreshed by the caller)
}

type proxyServer struct {
	opts      Options
	ca        *caManager
	cache     *agentCache
	transport *http.Transport
}

// Start runs the agent proxy until the process is terminated.
func Start(opts Options) error {
	ps := &proxyServer{
		opts:  opts,
		ca:    newCaManager(opts.ProxyToken),
		cache: newAgentCache(opts.ProxyToken),
		transport: &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	// warm up the intermediate CA so the first agent request isn't blocked on signing
	if err := ps.ca.ensureIntermediate(); err != nil {
		return fmt.Errorf("failed to initialize agent proxy CA: %w", err)
	}

	go ps.pollLoop()

	// Pre-flight: fail fast if something already listens on this port. A plain net.Listen(":port")
	// can bind one address family (e.g. IPv6) while another process holds the other (e.g. a process
	// on IPv4 127.0.0.1), which would silently split traffic, so probe both loopback families first.
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
			// back off briefly so a persistent accept error doesn't hot-spin the loop
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go ps.handleConn(conn)
	}
}

// portInUse reports the first loopback address that already has a listener on the port, or "".
// Probing both families catches the dual-stack split that a bare net.Listen would miss.
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

	reader := bufio.NewReader(clientConn)
	// Bound the time a client may take to send its first request so a stalled connection can't
	// pin a goroutine; subsequent keep-alive requests on the plain-HTTP path get the idle timeout.
	readTimeout := connectReadTimeout
	for {
		_ = clientConn.SetReadDeadline(time.Now().Add(readTimeout))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
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

// handleConnect serves a CONNECT request: authenticate, mint a leaf for the target hostname,
// complete the MITM TLS handshake, and serve tunnelled requests until the connection ends.
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

	// leaf is minted for the exact CONNECT hostname (design: CONNECT host is source of truth)
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

// handlePlainForward serves an absolute-form forward-proxy request (RFC 7230 §5.3.2) for a
// plain-HTTP upstream, applying the same auth, matching, and credential pipeline as the CONNECT
// path — there is just no TLS layer to intercept, and the agent JWT arrives on every request
// rather than once per tunnel. Only http:// is served: https:// absolute-form is rejected so
// the proxy can never be used to silently TLS-strip (HTTPS upstreams must arrive as CONNECT),
// and origin-form is rejected so the proxy ingress cannot be used as an origin server.
// It reports whether the connection may serve another keep-alive request.
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

	// URL.Hostname/Port handle bracketed IPv6 literals; default the port for the http scheme.
	// Per RFC 7230 §5.4 the absolute-form URL is authoritative for routing (the Host header is
	// not consulted; Go's ReadRequest already promotes the URL host into req.Host).
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

// parseConnectTarget splits a CONNECT authority-form target into hostname and port, defaulting
// the port to 443. Bracketed IPv6 literals ("[::1]", "[::1]:8443") are handled by SplitHostPort;
// anything it cannot parse even with the default port appended is rejected.
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

// serveTunnel reads requests off the terminated TLS connection, applies credentials, and forwards them.
func (ps *proxyServer) serveTunnel(tlsConn *tls.Conn, hostname, port, jwt string, scope agentScope) {
	tlsReader := bufio.NewReader(tlsConn)

	for {
		// Reap a tunnel that sits idle (or dribbles headers) between requests.
		_ = tlsConn.SetReadDeadline(time.Now().Add(idleTunnelTimeout))
		req, err := http.ReadRequest(tlsReader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Debug().Err(err).Msg("tunnel read ended")
			}
			return
		}
		// Clear the deadline for the forward: the upstream response may legitimately stream for a while.
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

	// rebuild the outbound request targeting the real upstream
	req.URL.Scheme = scheme
	req.URL.Host = net.JoinHostPort(hostname, port)
	req.RequestURI = ""

	if svc != nil {
		if err := applyCredentials(req, svc); err != nil {
			return nil, fmt.Errorf("failed to apply credentials: %w", err)
		}
	}

	stripHopByHopHeaders(req.Header)

	return ps.transport.RoundTrip(req)
}

// hopByHopHeaders are the standard hop-by-hop headers removed before forwarding,
// mirroring net/http/httputil.ReverseProxy.
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

// stripHopByHopHeaders removes the headers named in the Connection header plus the standard
// hop-by-hop set; they describe this hop's connection and must not be forwarded upstream.
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

// parseProxyAuth decodes the Proxy-Authorization Basic header into scope + agent JWT.
// userinfo layout: username = projectId, password = "<env>/<path>:<jwt>" (jwt last).
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

	// jwt is after the LAST colon (env/path contain no colons; JWT charset has none)
	lastColon := strings.LastIndex(password, ":")
	if lastColon == -1 {
		return agentScope{}, "", false
	}
	scopeStr := password[:lastColon]
	jwt := password[lastColon+1:]

	// scopeStr = "<env>/<path...>"
	slash := strings.Index(scopeStr, "/")
	var environment, secretPath string
	if slash == -1 {
		environment = scopeStr
		secretPath = "/"
	} else {
		environment = scopeStr[:slash]
		secretPath = scopeStr[slash:] // includes leading slash
	}

	if projectID == "" || environment == "" || jwt == "" {
		return agentScope{}, "", false
	}

	return agentScope{projectID: projectID, environment: environment, secretPath: secretPath}, jwt, true
}

// drainRequestBody consumes whatever the transport did not read of the request body so leftover
// bytes cannot desync the next http.ReadRequest on a keep-alive connection.
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
