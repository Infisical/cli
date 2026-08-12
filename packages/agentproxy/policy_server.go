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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	policyHeartbeatInterval = 1 * time.Minute
	policyShutdownTimeout   = 10 * time.Second

	// Returned to the agent for anything the intersection does not allow. Deliberately uniform: it says
	// the proxy refused the request without telling the agent which side of the intersection stopped it.
	policyDeniedBody = `{"error":"forbidden_by_policy","message":"This request is not allowed by the agent and user policies in effect."}`
)

// PolicyOptions configures the policy-mode proxy: the long-standing agent proxy registered in Infisical
// under Networking, which brokers on the intersection of an agent's policies and a user's.
type PolicyOptions struct {
	Port         int
	PollInterval time.Duration
	ProxyToken   func() string
}

type policyServer struct {
	opts      PolicyOptions
	ca        *caManager
	resolver  *policyResolver
	transport http.RoundTripper
}

// StartPolicyProxy runs the proxy until the process is signalled.
func StartPolicyProxy(opts PolicyOptions) error {
	if opts.ProxyToken == nil {
		return errors.New("the agent proxy needs an access token")
	}
	if opts.Port == 0 {
		opts.Port = 17323
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 60 * time.Second
	}

	ps := &policyServer{
		opts:      opts,
		ca:        newCaManager(opts.ProxyToken),
		resolver:  newPolicyResolver(opts.ProxyToken),
		transport: newUpstreamTransport(),
	}

	// Fail at startup rather than on the first request: without a signed intermediate the proxy cannot
	// terminate TLS for anything, and an operator wants to know that immediately.
	if err := ps.ca.ensureSigningCert(); err != nil {
		return fmt.Errorf("failed to get an intermediate CA signed by Infisical: %w", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", opts.Port))
	if err != nil {
		if inUse := portInUse(opts.Port); inUse != "" {
			return fmt.Errorf("port %d is already in use by %s", opts.Port, inUse)
		}
		return err
	}

	srv := &http.Server{
		Handler:           http.HandlerFunc(ps.dispatch),
		ReadHeaderTimeout: frontReadHeaderTimeout,
		IdleTimeout:       frontIdleTimeout,
		MaxHeaderBytes:    maxRequestHeaderBytes,
	}

	stop := make(chan struct{})
	go ps.pollLoop(stop)
	go ps.heartbeatLoop(stop)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		log.Info().Msgf("Infisical agent proxy listening on :%d", opts.Port)
		if serveErr := srv.Serve(newLimitListener(listener, maxConcurrentConns)); serveErr != nil &&
			!errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	select {
	case err := <-errCh:
		close(stop)
		return err
	case <-signals:
		log.Info().Msg("Shutting down the agent proxy")
	}

	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), policyShutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(ctx)
	ps.resolver.flushActivity()
	ps.resolver.close()
	return nil
}

func (ps *policyServer) pollLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(ps.opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ps.resolver.refreshActive()
			ps.resolver.flushActivity()
		case <-stop:
			return
		}
	}
}

func (ps *policyServer) heartbeatLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(policyHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := api.CallAgentProxyHeartbeat(resty.New().SetAuthToken(ps.opts.ProxyToken())); err != nil {
				log.Warn().Err(err).Msg("failed to report the agent proxy heartbeat")
			}
		case <-stop:
			return
		}
	}
}

// sessionToken pulls the session token out of Proxy-Authorization. Both forms are accepted because an
// agent's HTTP client decides which one it sends: Basic with the token as the username (what an
// http://<token>:@host:port proxy URL produces) and Bearer.
//
// The proxy URL needs the trailing colon after the token. urllib3 parses http://<token>@host as having
// no password and sends no Proxy-Authorization at all, so the request arrives here unauthenticated and
// gets a 407; curl and Node send the header either way.
func sessionToken(header string) (string, bool) {
	if strings.HasPrefix(header, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		return token, token != ""
	}
	if !strings.HasPrefix(header, "Basic ") {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return "", false
	}
	userinfo := string(decoded)
	if idx := strings.Index(userinfo, ":"); idx != -1 {
		// A token in either position: <token>: from a proxy URL with no password, or :<token>.
		if user := userinfo[:idx]; user != "" {
			return user, true
		}
		password := userinfo[idx+1:]
		return password, password != ""
	}
	return userinfo, userinfo != ""
}

func (ps *policyServer) dispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		ps.handleConnect(w, r)
		return
	}
	ps.handlePlainForward(w, r)
}

func (ps *policyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Everything that can produce an HTTP status happens before the hijack: afterwards there is no way to
	// send one.
	token, ok := sessionToken(r.Header.Get("Proxy-Authorization"))
	if !ok {
		writeProxyAuthChallenge(w)
		return
	}

	hostname, port, err := parseConnectTarget(r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid CONNECT target %q", r.Host), http.StatusBadRequest)
		return
	}

	// Resolve before minting a leaf: otherwise any syntactically valid header forces unbounded key
	// generation and leaf-cache growth.
	session, err := ps.resolver.get(token)
	if err != nil {
		if isAuthError(err) {
			http.Error(w, "proxy authorization failed", http.StatusForbidden)
		} else {
			http.Error(w, "failed to resolve the session's policies", http.StatusBadGateway)
		}
		return
	}

	// CONNECT carries only host and port. A host no rule could ever match is refused here; anything else
	// opens the tunnel and is decided per request inside it, where the method and path are known.
	allowlisted := hostAllowed(session.allowedHosts, hostname)
	if !allowlisted && !agentCoversHost(session.agentPolicies, hostname, port) {
		ps.record(session, "blocked", r.Method, hostname, port, "", 0, "", "no policy covers this host")
		http.Error(w, "host is not allowed by policy", http.StatusForbidden)
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
	_ = tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	ps.serveTunnel(tlsConn, hostname, port, token)
}

func (ps *policyServer) serveTunnel(tlsConn *tls.Conn, hostname, port, token string) {
	listener := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ps.forwardHTTP(w, r, "https", hostname, port, token)
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

func (ps *policyServer) handlePlainForward(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(plainReadTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(plainWriteTimeout))

	// Only absolute-form http:// is served. Accepting https:// here would let the proxy be used to
	// TLS-strip; HTTPS has to arrive as CONNECT.
	if !strings.EqualFold(r.URL.Scheme, "http") || r.URL.Host == "" {
		http.Error(w, "non-CONNECT requests must be absolute-form http:// (use CONNECT for https:// upstreams)", http.StatusBadRequest)
		return
	}

	token, ok := sessionToken(r.Header.Get("Proxy-Authorization"))
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

	ps.forwardHTTP(w, r, "http", hostname, port, token)
}

func (ps *policyServer) forwardHTTP(w http.ResponseWriter, r *http.Request, scheme, hostname, port, token string) {
	// TRACE/TRACK make the upstream reflect the request, including an injected credential, back in the
	// response body, which would hand the agent a secret it cannot fetch directly.
	if r.Method == http.MethodTrace || r.Method == "TRACK" {
		http.Error(w, "method not allowed through the agent proxy", http.StatusMethodNotAllowed)
		return
	}

	session, err := ps.resolver.get(token)
	if err != nil {
		if isAuthError(err) {
			http.Error(w, "proxy authorization failed", http.StatusForbidden)
			return
		}
		http.Error(w, "failed to resolve the session's policies", http.StatusBadGateway)
		return
	}

	matched, userAllowed := evaluate(session.agentPolicies, session.userPolicies, scheme, hostname, port, r.URL.Path, r.Method)
	allowlisted := hostAllowed(session.allowedHosts, hostname)

	switch {
	case matched != nil && userAllowed:
		// Brokered: both sides allow it, so the credential goes on.
	case allowlisted:
		// Passes through with no credential. Infrastructure hosts an agent needs to function live here.
	default:
		reason := "no agent policy allows this request"
		if matched != nil && !userAllowed {
			reason = "no user policy allows this request"
		}
		ps.record(session, "blocked", r.Method, hostname, port, r.URL.Path, http.StatusForbidden, policyName(matched), reason)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(policyDeniedBody))
		return
	}

	r.URL.Scheme = scheme
	r.URL.Host = net.JoinHostPort(hostname, port)
	// Pin Host to the matched authority: the inner tunnel Host is agent-controlled and Go forwards it
	// verbatim, which would let a matched CONNECT deliver the credential to a different vhost.
	r.Host = hostHeaderForScheme(scheme, r.URL.Host)
	r.RequestURI = ""

	// Strip hop-by-hop before injecting, so a client's Connection header cannot delete the credential.
	stripHopByHopHeaders(r.Header)

	decision := "passthrough"
	if matched != nil && userAllowed {
		if _, applyErr := applyCredentials(r, matched.credentials); applyErr != nil {
			ps.record(session, "error", r.Method, hostname, port, r.URL.Path, http.StatusBadGateway, matched.name, "failed to apply credentials")
			http.Error(w, "failed to apply credentials", http.StatusBadGateway)
			return
		}
		decision = "brokered"
	}

	resp, err := ps.transport.RoundTrip(r)
	if err != nil {
		ps.record(session, "error", r.Method, hostname, port, r.URL.Path, http.StatusBadGateway, policyName(matched), err.Error())
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(flushingWriter{w: w}, resp.Body)

	ps.record(session, decision, r.Method, hostname, port, r.URL.Path, resp.StatusCode, policyName(matched), "")
}

func policyName(policy *resolvedAgentPolicy) string {
	if policy == nil {
		return ""
	}
	return policy.name
}

func (ps *policyServer) record(
	session *sessionEntry,
	decision, method, host, port, path string,
	status int,
	policy, reason string,
) {
	portNum, _ := strconv.Atoi(port)
	if portNum == 0 {
		portNum = 443
	}
	if path == "" {
		path = "/"
	}
	if len(path) > maxLoggedPathLen {
		path = path[:maxLoggedPathLen]
	}

	log.WithLevel(levelFor(decision)).
		Str("event", "agent-proxy.request").
		Str("decision", decision).
		Str("agent", session.agentName).
		Str("method", method).
		Str("host", host).
		Int("port", portNum).
		Str("path", path).
		Int("status", status).
		Str("policy", policy).
		Str("reason", reason).
		Msg("agent request")

	ps.resolver.recordActivity(session.token, api.AgentSessionActivityEvent{
		Decision:   decision,
		Method:     method,
		Host:       host,
		Port:       portNum,
		Path:       path,
		StatusCode: status,
		PolicyName: policy,
		Reason:     reason,
	})
}
