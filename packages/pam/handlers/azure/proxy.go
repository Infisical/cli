package azure

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type AzureProxyConfig struct {
	Tokens        map[string]string
	SessionID     string
	SessionLogger session.SessionLogger
}

type AzureProxy struct {
	config AzureProxyConfig
	caCert *x509.Certificate
	caKey  crypto.Signer
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.n <= 0 {
		return len(p), nil
	}
	if len(p) > lw.n {
		p = p[:lw.n]
	}
	n, err := lw.w.Write(p)
	lw.n -= n
	return n, err
}

func NewAzureProxy(config AzureProxyConfig) *AzureProxy {
	return &AzureProxy{config: config}
}

const maxPEMSize = 1 << 20 // 1 MiB

func readLengthPrefixed(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length > maxPEMSize {
		return nil, fmt.Errorf("length prefix %d exceeds max allowed size", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *AzureProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	l := log.With().Str("sessionID", p.config.SessionID).Logger()

	l.Info().Msg("New Azure CLI connection, reading CA from client")

	caCertPEM, err := readLengthPrefixed(clientConn)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}
	caKeyPEM, err := readLengthPrefixed(clientConn)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	p.caCert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	p.caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	l.Info().Msg("CA loaded, starting HTTP proxy")

	reader := bufio.NewReader(clientConn)

	transport := &http.Transport{
		DisableKeepAlives: false,
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
		TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}
	client := &http.Client{Transport: transport}

	for {
		select {
		case <-ctx.Done():
			l.Info().Msg("Context cancelled, closing Azure proxy connection")
			return ctx.Err()
		default:
		}

		reqCh := make(chan *http.Request, 1)
		errCh := make(chan error, 1)

		go func() {
			req, err := http.ReadRequest(reader)
			if err != nil {
				errCh <- err
			} else {
				reqCh <- req
			}
		}()

		var req *http.Request
		select {
		case <-ctx.Done():
			l.Info().Msg("Context cancelled while reading HTTP request")
			return ctx.Err()
		case err := <-errCh:
			if errors.Is(err, io.EOF) {
				l.Info().Msg("Client closed connection")
				return nil
			}
			l.Error().Err(err).Msg("Failed to read HTTP request")
			return fmt.Errorf("failed to read HTTP request: %w", err)
		case req = <-reqCh:
		}

		if req.Method == http.MethodConnect {
			return p.handleConnect(ctx, clientConn, req, client, l)
		}

		if err := p.handleRequest(ctx, clientConn, req, client, l); err != nil {
			return err
		}
	}
}

func (p *AzureProxy) handleConnect(ctx context.Context, clientConn net.Conn, connectReq *http.Request, client *http.Client, l zerolog.Logger) error {
	targetHost := connectReq.Host
	if !strings.Contains(targetHost, ":") {
		targetHost += ":443"
	}

	hostname := strings.Split(targetHost, ":")[0]
	if !isAzureHost(hostname) {
		writeErrorResponseTo(clientConn, fmt.Sprintf("host %q is not an allowed Azure endpoint", hostname))
		return fmt.Errorf("rejected CONNECT to non-Azure host: %s", hostname)
	}

	_, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send CONNECT response: %w", err)
	}

	l.Info().Str("host", targetHost).Msg("CONNECT tunnel established, starting TLS termination")

	tlsCert, err := p.generateSignedCert(hostname)
	if err != nil {
		return fmt.Errorf("failed to generate TLS cert for %s: %w", hostname, err)
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	tlsReader := bufio.NewReader(tlsConn)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		reqCh := make(chan *http.Request, 1)
		errCh := make(chan error, 1)

		go func() {
			req, err := http.ReadRequest(tlsReader)
			if err != nil {
				errCh <- err
			} else {
				reqCh <- req
			}
		}()

		var req *http.Request
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if errors.Is(err, io.EOF) {
				l.Info().Msg("Client closed TLS connection")
				return nil
			}
			return fmt.Errorf("failed to read HTTP request from TLS: %w", err)
		case req = <-reqCh:
		}

		if req.Host == "" {
			req.Host = hostname
		}

		if err := p.handleRequest(ctx, tlsConn, req, client, l); err != nil {
			return err
		}
	}
}

func isTokenEndpoint(path string) bool {
	return strings.Contains(path, "/oauth2/") && strings.HasSuffix(path, "/token")
}

func (p *AzureProxy) handleRequest(_ context.Context, writer io.Writer, req *http.Request, client *http.Client, l zerolog.Logger) error {
	requestId := uuid.New()

	host := req.Host
	if req.URL.Scheme != "" && req.URL.Host != "" {
		host = req.URL.Host
	}
	hostname := host
	if strings.Contains(hostname, ":") {
		hostname = strings.Split(hostname, ":")[0]
	}

	if !isAzureHost(hostname) {
		l.Warn().Str("host", host).Msg("Rejected non-Azure request")
		writeErrorResponseTo(writer, fmt.Sprintf("host %q is not an allowed Azure endpoint", host))
		return nil
	}

	if isLoginHost(hostname) {
		if isTokenEndpoint(req.URL.Path) {
			_, _ = io.Copy(io.Discard, req.Body)
			req.Body.Close()
			l.Info().Str("reqId", requestId.String()).Msg("Intercepted Entra ID token request, returning placeholder")
			return writePlaceholderTokenResponse(writer)
		}
		return p.forward(writer, req, client, l, "", false, requestId)
	}

	audience, _ := azureHostAudience(hostname)
	token := p.config.Tokens[audience]
	if token == "" {
		l.Warn().Str("host", host).Str("audience", audience).Msg("No brokered token for Azure plane")
		writeErrorResponseTo(writer, fmt.Sprintf("no brokered access for %q; the service principal may lack permissions for this Azure service", host))
		return nil
	}
	return p.forward(writer, req, client, l, token, isVaultHost(hostname), requestId)
}

func (p *AzureProxy) forward(writer io.Writer, req *http.Request, client *http.Client, l zerolog.Logger, injectToken string, redactBody bool, requestId uuid.UUID) error {
	const maxLogBodySize = 1 << 20 // 1 MiB cap for audit-logged bodies
	redactedMarker := []byte("[redacted: Key Vault body]")

	logRequest := injectToken != ""

	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		l.Error().Err(err).Msg("Failed to read request body")
		writeErrorResponseTo(writer, "failed to read request body")
		return err
	}

	if logRequest {
		loggedReqBody := reqBody
		if len(loggedReqBody) > maxLogBodySize {
			loggedReqBody = loggedReqBody[:maxLogBodySize]
		}
		if redactBody && len(loggedReqBody) > 0 {
			loggedReqBody = redactedMarker
		}
		if err := p.config.SessionLogger.LogHttpEvent(session.HttpEvent{
			Timestamp: time.Now(),
			RequestId: requestId.String(),
			EventType: session.HttpEventRequest,
			URL:       req.URL.String(),
			Method:    req.Method,
			Headers:   req.Header,
			Body:      loggedReqBody,
		}); err != nil {
			l.Error().Err(err).Msg("Failed to log HTTP request event")
		}
	}

	host := req.Host
	path := req.URL.RequestURI()
	if req.URL.Scheme != "" && req.URL.Host != "" {
		host = req.URL.Host
		path = req.URL.Path
		if req.URL.RawQuery != "" {
			path += "?" + req.URL.RawQuery
		}
	}

	targetURL, err := url.Parse(fmt.Sprintf("https://%s%s", host, path))
	if err != nil {
		l.Error().Err(err).Msg("Failed to parse target URL")
		writeErrorResponseTo(writer, "failed to parse target URL")
		return nil
	}

	proxyReq, err := http.NewRequest(req.Method, targetURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		l.Error().Err(err).Msg("Failed to create proxy request")
		writeErrorResponseTo(writer, "failed to create proxy request")
		return nil
	}

	proxyReq.Header = req.Header.Clone()
	proxyReq.Header.Del("Accept-Encoding")
	if injectToken != "" {
		proxyReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", injectToken))
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		l.Error().Err(err).Str("url", targetURL.String()).Msg("Failed to forward request to Azure")
		writeErrorResponseTo(writer, "failed to forward request to Azure")
		return nil
	}

	resp.Header.Del("Connection")

	var bodyCopy bytes.Buffer
	if logRequest && !redactBody {
		resp.Body = struct {
			io.ReadCloser
		}{
			ReadCloser: io.NopCloser(io.TeeReader(resp.Body, &limitedWriter{w: &bodyCopy, n: maxLogBodySize})),
		}
	}

	if err := resp.Write(writer); err != nil {
		if errors.Is(err, io.EOF) {
			l.Info().Msg("Client closed connection")
		} else {
			l.Error().Err(err).Msg("Failed to write response to connection")
			resp.Body.Close()
			return fmt.Errorf("failed to write response to connection: %w", err)
		}
	}

	resp.Body.Close()

	if logRequest {
		respBody := bodyCopy.Bytes()
		if redactBody {
			respBody = redactedMarker
		}
		if err := p.config.SessionLogger.LogHttpEvent(session.HttpEvent{
			Timestamp: time.Now(),
			RequestId: requestId.String(),
			EventType: session.HttpEventResponse,
			Status:    resp.Status,
			Headers:   resp.Header,
			Body:      respBody,
		}); err != nil {
			l.Error().Err(err).Msg("Failed to log HTTP response event")
		}
	}

	return nil
}

func (p *AzureProxy) generateSignedCert(hostname string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func writePlaceholderTokenResponse(w io.Writer) error {
	token := makePlaceholderToken(3600)
	body := fmt.Sprintf(`{"token_type":"Bearer","expires_in":3600,"ext_expires_in":3600,"access_token":%q}`, token)
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(body), body)
	_, err := w.Write([]byte(resp))
	return err
}

func makePlaceholderToken(expiresInSec int64) string {
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	now := time.Now().Unix()
	header := enc([]byte(`{"typ":"JWT","alg":"RS256","kid":"infisical-pam"}`))
	payload := enc([]byte(fmt.Sprintf(
		`{"aud":"https://management.azure.com","iss":"https://sts.windows.net/infisical-pam/","iat":%d,"nbf":%d,"exp":%d,"appid":"infisical-pam","tid":"infisical-pam","ver":"1.0"}`,
		now, now, now+expiresInSec,
	)))
	sig := enc([]byte("infisical-pam-proxy-managed"))
	return header + "." + payload + "." + sig
}

func isLoginHost(host string) bool {
	return strings.EqualFold(host, "login.microsoftonline.com")
}

func isVaultHost(host string) bool {
	return strings.HasSuffix(strings.ToLower(host), ".vault.azure.net")
}

func azureHostAudience(host string) (string, bool) {
	h := strings.ToLower(host)
	switch {
	case h == "management.azure.com":
		return "arm", true
	case h == "graph.microsoft.com":
		return "graph", true
	case strings.HasSuffix(h, ".vault.azure.net"):
		return "keyvault", true
	case strings.HasSuffix(h, ".blob.core.windows.net"),
		strings.HasSuffix(h, ".queue.core.windows.net"),
		strings.HasSuffix(h, ".table.core.windows.net"),
		strings.HasSuffix(h, ".file.core.windows.net"),
		strings.HasSuffix(h, ".dfs.core.windows.net"):
		return "storage", true
	}
	return "", false
}

func isAzureHost(host string) bool {
	if strings.Contains(host, "@") {
		return false
	}
	u, err := url.Parse("https://" + host)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if isLoginHost(h) {
		return true
	}
	_, ok := azureHostAudience(h)
	return ok
}

func writeErrorResponseTo(w io.Writer, message string) {
	body := fmt.Sprintf("{\"message\": \"gateway: %s\"}", message)
	resp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	w.Write([]byte(resp))
}
