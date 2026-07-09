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

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	UnmatchedAllow = "allow"
	UnmatchedBlock = "block"
)

type Options struct {
	Port          int
	UnmatchedHost string        // allow | block
	PollInterval  time.Duration // cache refresh cadence
	ProxyToken    string        // the agent proxy MI's own access token
	CaHTTPClient  *resty.Client // authenticated as the proxy MI, for CA signing
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
		ca:    newCaManager(opts.CaHTTPClient),
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

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", opts.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", opts.Port, err)
	}
	log.Info().Msgf("Infisical agent proxy listening on :%d", opts.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Warn().Err(err).Msg("failed to accept connection")
			continue
		}
		go ps.handleConn(conn)
	}
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
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		writeProxyResponse(clientConn, http.StatusMethodNotAllowed, "only CONNECT is supported")
		return
	}

	scope, jwt, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok {
		clientConn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")) // #nosec G104
		return
	}

	targetHost := req.Host
	if !strings.Contains(targetHost, ":") {
		targetHost += ":443"
	}
	hostname, port, err := net.SplitHostPort(targetHost)
	if err != nil {
		hostname = strings.Split(targetHost, ":")[0]
		port = "443"
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
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	ps.serveTunnel(tlsConn, hostname, port, jwt, scope)
}

// serveTunnel reads requests off the terminated TLS connection, applies credentials, and forwards them.
func (ps *proxyServer) serveTunnel(tlsConn *tls.Conn, hostname, port, jwt string, scope agentScope) {
	tlsReader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(tlsReader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Debug().Err(err).Msg("tunnel read ended")
			}
			return
		}

		resp, err := ps.forward(req, hostname, port, jwt, scope)
		if err != nil {
			writeHTTPError(tlsConn, http.StatusBadGateway, err.Error())
			return
		}

		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
	}
}

func (ps *proxyServer) forward(req *http.Request, hostname, port, jwt string, scope agentScope) (*http.Response, error) {
	services, err := ps.cache.get(jwt, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve agent permissions: %w", err)
	}

	svc := bestMatch(services, hostname, port, req.URL.Path)

	if svc == nil && ps.opts.UnmatchedHost == UnmatchedBlock {
		return nil, fmt.Errorf("host %q has no matching proxied service (blocked by policy)", hostname)
	}

	// rebuild the outbound request targeting the real upstream
	req.URL.Scheme = "https"
	req.URL.Host = net.JoinHostPort(hostname, port)
	req.RequestURI = ""

	if svc != nil {
		if err := applyCredentials(req, svc); err != nil {
			return nil, fmt.Errorf("failed to apply credentials: %w", err)
		}
	}

	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	return ps.transport.RoundTrip(req)
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

func writeProxyResponse(conn net.Conn, status int, msg string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(msg), msg) // #nosec G104
}

func writeHTTPError(conn io.Writer, status int, msg string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(msg), msg) // #nosec G104
}
