package broker

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

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

func (p *Proxy) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.pem", p.handleCAPEM)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.listener = ln
	log.Info().Str("addr", addr).Msg("Broker proxy listening")

	for {
		conn, err := ln.Accept()
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

func (p *Proxy) Close() error {
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

	// TLS handshake with the client using a minted leaf cert
	tlsConfig := &tls.Config{
		GetCertificate: p.ca.GetCertificate,
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Error().Err(err).Str("host", host).Msg("TLS handshake with client failed")
		return
	}
	defer tlsConn.Close()

	// Read the actual HTTP request from the TLS tunnel
	br := bufio.NewReader(tlsConn)
	tunnelReq, err := http.ReadRequest(br)
	if err != nil {
		log.Error().Err(err).Str("host", host).Msg("Failed to read tunneled request")
		return
	}
	tunnelReq.URL.Scheme = "https"
	tunnelReq.URL.Host = req.Host

	path := tunnelReq.URL.Path
	log.Info().Str("host", host).Str("method", tunnelReq.Method).Str("path", path).Msg("Proxying request")

	rules := p.getRules()
	matched := MatchRule(host, port, path, rules)

	if matched == nil {
		if p.blockUnknownHosts && !p.isHostAllowed(host) {
			log.Warn().Str("host", host).Msg("No matching rule, returning 403")
			p.writeForbidden(tlsConn, host)
			return
		}
		log.Debug().Str("host", host).Msg("No matching rule, passing through")
	} else {
		log.Info().Str("host", host).Str("authType", matched.AuthType).Str("secretKey", matched.SecretKey).Msg("Matched rule, injecting credentials")
		InjectAuth(tunnelReq, matched)
	}

	// Forward to upstream
	upstreamAddr := req.Host
	if !strings.Contains(upstreamAddr, ":") {
		upstreamAddr = upstreamAddr + ":443"
	}
	upstreamConn, err := tls.Dial("tcp", upstreamAddr, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		log.Error().Err(err).Str("upstream", upstreamAddr).Msg("Failed to connect to upstream")
		writeErrorResponse(tlsConn, 502, "Bad Gateway")
		return
	}
	defer upstreamConn.Close()

	tunnelReq.Header.Del("Proxy-Authorization")
	tunnelReq.Header.Del("Proxy-Connection")
	tunnelReq.RequestURI = ""
	if err := tunnelReq.Write(upstreamConn); err != nil {
		log.Error().Err(err).Msg("Failed to write to upstream")
		return
	}

	upstreamBr := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamBr, tunnelReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read upstream response")
		return
	}
	defer resp.Body.Close()

	log.Info().Str("host", host).Int("status", resp.StatusCode).Msg("Upstream response")
	resp.Header.Del("Set-Cookie")
	resp.Write(tlsConn)
}

func (p *Proxy) handleForward(clientConn net.Conn, req *http.Request) {
	host, port := ExtractHostPort(req.Host)
	if port == 443 {
		port = 80
	}
	path := req.URL.Path
	rules := p.getRules()
	matched := MatchRule(host, port, path, rules)

	if matched == nil {
		p.writeForbiddenConn(clientConn, host)
		return
	}

	InjectAuth(req, matched)

	// Forward
	upstream, err := net.Dial("tcp", req.Host)
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

	resp.Header.Del("Set-Cookie")
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
