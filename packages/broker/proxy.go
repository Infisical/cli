package broker

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/ca"
	"github.com/rs/zerolog/log"
)

type ProposalRequest struct {
	SecretKey      string `json:"secretKey"`
	Host           string `json:"host"`
	AuthType       string `json:"authType"`
	HeaderName     string `json:"headerName,omitempty"`
	Username       string `json:"username,omitempty"`
	HeaderTemplate string `json:"headerTemplate,omitempty"`
	Comment        string `json:"comment,omitempty"`
}

type ProposalResponse struct {
	Status    string `json:"status"`
	ReviewURL string `json:"reviewUrl,omitempty"`
	Message   string `json:"message"`
}

type ProposalFunc func(req ProposalRequest) (*ProposalResponse, error)

type Proxy struct {
	ca                *ca.CA
	rules             []ParsedRule
	allowedHosts      map[string]bool
	blockUnknownHosts bool
	proposalFn        ProposalFunc
	rulesMu           sync.RWMutex
	listener          net.Listener
	upstream          *http.Transport
}

func NewProxy(certAuthority *ca.CA, rules []ParsedRule, allowedHosts []string, blockUnknownHosts bool) *Proxy {
	hostMap := make(map[string]bool)
	for _, h := range allowedHosts {
		hostMap[strings.ToLower(strings.TrimSpace(h))] = true
	}
	return &Proxy{
		ca:                certAuthority,
		rules:             rules,
		allowedHosts:      hostMap,
		blockUnknownHosts: blockUnknownHosts,
		upstream: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		},
	}
}

func (p *Proxy) UpdateRules(rules []ParsedRule) {
	p.rulesMu.Lock()
	p.rules = rules
	p.rulesMu.Unlock()
}

func (p *Proxy) getRules() []ParsedRule {
	p.rulesMu.RLock()
	defer p.rulesMu.RUnlock()
	return p.rules
}

func (p *Proxy) isHostAllowed(host string) bool {
	return p.allowedHosts[strings.ToLower(host)]
}

func (p *Proxy) SetProposalFunc(fn ProposalFunc) {
	p.proposalFn = fn
}

func (p *Proxy) handleInternal(conn net.Conn, req *http.Request) {
	switch req.URL.Path {
	case "/_internal/propose":
		p.handlePropose(conn, req)
	case "/_internal/discover":
		p.handleDiscover(conn, req)
	default:
		writeErrorResponse(conn, 404, "Not Found")
	}
}

func (p *Proxy) handlePropose(conn net.Conn, req *http.Request) {
	if req.Method != http.MethodPost {
		writeErrorResponse(conn, 405, "Method Not Allowed")
		return
	}
	if p.proposalFn == nil {
		writeJSONResponse(conn, 501, ProposalResponse{Status: "error", Message: "Proposals not configured"})
		return
	}

	var proposal ProposalRequest
	if err := json.NewDecoder(req.Body).Decode(&proposal); err != nil {
		writeJSONResponse(conn, 400, ProposalResponse{Status: "error", Message: "Invalid request body"})
		return
	}

	if proposal.SecretKey == "" || proposal.Host == "" || proposal.AuthType == "" {
		writeJSONResponse(conn, 400, ProposalResponse{Status: "error", Message: "secretKey, host, and authType are required"})
		return
	}

	log.Info().Str("secretKey", proposal.SecretKey).Str("host", proposal.Host).Str("authType", proposal.AuthType).Msg("Received proposal")

	resp, err := p.proposalFn(proposal)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create proposal")
		writeJSONResponse(conn, 500, ProposalResponse{Status: "error", Message: err.Error()})
		return
	}

	writeJSONResponse(conn, 200, resp)
}

func (p *Proxy) handleDiscover(conn net.Conn, req *http.Request) {
	rules := p.getRules()
	type service struct {
		Host     string `json:"host"`
		AuthType string `json:"authType"`
	}
	services := make([]service, 0, len(rules))
	seen := make(map[string]bool)
	for _, r := range rules {
		key := r.Host + ":" + r.AuthType
		if !seen[key] {
			services = append(services, service{Host: r.Host, AuthType: r.AuthType})
			seen[key] = true
		}
	}
	writeJSONResponse(conn, 200, map[string]interface{}{"services": services})
}

func writeJSONResponse(conn net.Conn, code int, body interface{}) {
	data, _ := json.Marshal(body)
	resp := fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", code, len(data), data)
	conn.Write([]byte(resp))
}

func (p *Proxy) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.listener = ln
	return nil
}

func (p *Proxy) Serve() error {
	if p.listener == nil {
		return fmt.Errorf("proxy: not listening, call Listen first")
	}
	log.Info().Str("addr", p.listener.Addr().String()).Msg("Broker proxy listening")
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			log.Error().Err(err).Msg("Accept error")
			continue
		}
		go p.handleConnection(conn)
	}
}

func (p *Proxy) ListenAndServe(addr string) error {
	if err := p.Listen(addr); err != nil {
		return err
	}
	return p.Serve()
}

func (p *Proxy) Addr() net.Addr {
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}

func (p *Proxy) Close() error {
	p.upstream.CloseIdleConnections()
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req)
	} else if req.URL.Path == "/ca.pem" {
		p.serveCAPEM(conn, req)
	} else if strings.HasPrefix(req.URL.Path, "/_internal/") {
		p.handleInternal(conn, req)
	} else {
		p.handleForward(conn, req)
	}
}

func (p *Proxy) handleCAPEM(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(p.ca.CertPEM())
}

func (p *Proxy) serveCAPEM(conn net.Conn, req *http.Request) {
	pem := p.ca.CertPEM()
	resp := &http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(pem))),
	}
	resp.Header.Set("Content-Type", "application/x-pem-file")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(pem)))
	resp.Write(conn)
}

func (p *Proxy) handleConnect(clientConn net.Conn, req *http.Request) {
	host, port := ExtractHostPort(req.Host)
	log.Info().Str("host", host).Int("port", port).Msg("CONNECT request")

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Check if this host needs credential injection
	// For hosts without proxy configs (passthrough), do pure TCP tunneling
	// without any request parsing or TLS termination overhead.
	rules := p.getRules()
	matched := MatchRule(host, port, "/", rules)

	if matched == nil {
		if p.blockUnknownHosts && !p.isHostAllowed(host) {
			log.Warn().Str("host", host).Msg("No matching rule, returning 403")
			tlsConn := tls.Server(clientConn, &tls.Config{GetCertificate: p.ca.GetCertificate})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			p.writeForbidden(tlsConn, host)
			tlsConn.Close()
			return
		}
		// Passthrough: pure TCP tunnel, no MITM
		log.Debug().Str("host", host).Msg("No matching rule, tunneling without MITM")
		upstreamAddr := req.Host
		if !strings.Contains(upstreamAddr, ":") {
			upstreamAddr = upstreamAddr + ":443"
		}
		upstreamConn, err := net.Dial("tcp", upstreamAddr)
		if err != nil {
			return
		}
		defer upstreamConn.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(upstreamConn, clientConn); done <- struct{}{} }()
		go func() { io.Copy(clientConn, upstreamConn); done <- struct{}{} }()
		<-done
		return
	}

	// Host has a proxy config: MITM to inject credentials
	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: p.ca.GetCertificate,
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Error().Err(err).Str("host", host).Msg("TLS handshake with client failed")
		return
	}

	connectHost := req.Host
	if !strings.Contains(connectHost, ":") {
		connectHost = connectHost + ":443"
	}

	listener := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler:           p.forwardMITMRequest(connectHost, host, port),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateHijacked || state == http.StateClosed {
				_ = listener.Close()
			}
		},
	}
	_ = srv.Serve(listener)
}

func (p *Proxy) forwardMITMRequest(connectHost string, host string, port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules := p.getRules()
		matched := MatchRule(host, port, r.URL.Path, rules)

		if matched == nil {
			log.Debug().Str("host", host).Str("path", r.URL.Path).Msg("No rule matches this path, forwarding without injection")
		} else {
			log.Info().Str("host", host).Str("method", r.Method).Str("path", r.URL.Path).Str("authType", matched.AuthType).Str("secretKey", matched.SecretKey).Msg("Matched rule, injecting credentials")
			InjectAuth(r, matched)
		}

		outURL := &url.URL{
			Scheme:   "https",
			Host:     connectHost,
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
		}

		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
		if err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		for k, vv := range r.Header {
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
		outReq.ContentLength = r.ContentLength
		outReq.Header.Del("Proxy-Authorization")
		outReq.Header.Del("Proxy-Connection")
		outReq.Host = connectHost

		resp, err := p.upstream.RoundTrip(outReq)
		if err != nil {
			log.Error().Err(err).Str("host", connectHost).Msg("Upstream request failed")
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		var dst io.Writer = w
		if f, ok := w.(http.Flusher); ok {
			dst = &flushingWriter{w: w, f: f}
		}
		io.Copy(dst, resp.Body)
	}
}

func (p *Proxy) handleForward(clientConn net.Conn, req *http.Request) {
	host, port := ExtractHostPort(req.Host)
	if port == 0 {
		port = 80
	}
	path := req.URL.Path
	rules := p.getRules()
	matched := MatchRule(host, port, path, rules)

	if matched == nil {
		if p.blockUnknownHosts && !p.isHostAllowed(host) {
			p.writeForbiddenConn(clientConn, host)
			return
		}
		// Passthrough: forward without credential injection
		log.Debug().Str("host", host).Msg("No matching rule, forwarding HTTP request without injection")
	} else {
		InjectAuth(req, matched)
	}

	// Build upstream URL
	upstreamHost := req.Host
	if !strings.Contains(upstreamHost, ":") {
		upstreamHost = upstreamHost + ":80"
	}

	upstream, err := net.Dial("tcp", upstreamHost)
	if err != nil {
		writeErrorResponse(clientConn, 502, "Bad Gateway")
		return
	}
	defer upstream.Close()

	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.RequestURI = req.URL.RequestURI()
	if err := req.Write(upstream); err != nil {
		return
	}

	upstreamBr := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamBr, req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	resp.Write(clientConn)
}

func (p *Proxy) writeForbidden(w io.Writer, host string) {
	hint := map[string]interface{}{
		"error":   "forbidden",
		"message": fmt.Sprintf("No proxy rule matching host '%s'", host),
		"proposal_hint": map[string]interface{}{
			"host":                 host,
			"supported_auth_types": []string{"bearer", "basic", "api-key", "custom", "passthrough"},
		},
	}
	body, _ := json.Marshal(hint)
	resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	w.Write([]byte(resp))
}

func (p *Proxy) writeForbiddenConn(conn net.Conn, host string) {
	p.writeForbidden(conn, host)
}

func writeErrorResponse(w io.Writer, code int, message string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", code, message, len(message), message)
	w.Write([]byte(resp))
}

type oneShotListener struct {
	conn   net.Conn
	yield  chan net.Conn
	closed chan struct{}
}

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{
		conn:   c,
		yield:  make(chan net.Conn, 1),
		closed: make(chan struct{}),
	}
	l.yield <- c
	return l
}

var errListenerClosed = errors.New("broker: one-shot listener closed")

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.yield:
		return c, nil
	case <-l.closed:
		return nil, errListenerClosed
	}
}

func (l *oneShotListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

type flushingWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushingWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.f.Flush()
	}
	return n, err
}
