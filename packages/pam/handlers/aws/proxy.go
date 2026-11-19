package aws

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
)

const (
	maxPEMSize        = 1 << 20   // 1 MiB
	maxLoggedBodySize = 1 << 20   // 1 MiB of each body goes to the session log
	maxHashedBodySize = 128 << 20 // a body the client sent without its hash is buffered to hash it

	unsignedPayloadTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

// Every session on the gateway shares this, so parallel connections can't buffer more than it between them
var hashedBodies = semaphore.NewWeighted(2 * maxHashedBodySize)

// The domains AWS serves its APIs from. The gateway only signs requests bound for these, so a session
// can't use it to reach anything else on the gateway's network.
var awsDomainSuffixes = []string{"amazonaws.com", "amazonaws.com.cn", "api.aws"}

// Credentials are the STS credentials the gateway signs with. They never leave the gateway.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// RefusalError is Infisical's reason for no longer serving a session, such as an admin terminating it. The
// client is shown the reason, where any other credentials failure is reported as the gateway's own.
type RefusalError struct {
	Reason string
}

func (e *RefusalError) Error() string { return e.Reason }

type AWSProxyConfig struct {
	SessionID     string
	SessionLogger session.SessionLogger
	// Called for every request, so a session that outlives one set of STS credentials signs with the
	// next. Expected to cache.
	GetCredentials func() (Credentials, error)
}

type AWSProxy struct {
	config AWSProxyConfig
	caCert *x509.Certificate
	caKey  crypto.Signer
	signer *v4.Signer
	client *http.Client
}

func NewAWSProxy(config AWSProxyConfig) *AWSProxy {
	return &AWSProxy{
		config: config,
		signer: v4.NewSigner(),
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				// The response is relayed byte for byte to an HTTP/1.1 client, so neither HTTP/2 nor
				// transparent decompression may reshape it on the way through
				TLSNextProto:       make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
				DisableCompression: true,
			},
			// The client follows a redirect itself (S3 sends one to a bucket's region), so the request
			// to the new location comes back through here and is signed for it
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// IsAWSHost reports whether host, with or without a port, is in one of the domains AWS serves its APIs from.
func IsAWSHost(host string) bool {
	if strings.Contains(host, "@") {
		return false
	}
	u, err := url.Parse("https://" + host)
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, suffix := range awsDomainSuffixes {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return true
		}
	}
	return false
}

func (p *AWSProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	l := log.With().Str("sessionID", p.config.SessionID).Logger()

	if err := p.loadCA(clientConn); err != nil {
		return err
	}

	reader := newRequestReader(clientConn)
	for {
		req, err := reader.read(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("failed to read HTTP request: %w", err)
		}

		if req.Method == http.MethodConnect {
			return p.handleConnect(ctx, clientConn, req, l)
		}

		keepOpen, err := p.handleRequest(ctx, clientConn, req, "", l)
		if err != nil || !keepOpen {
			return err
		}
	}
}

func (p *AWSProxy) loadCA(conn net.Conn) error {
	caCertPEM, err := readLengthPrefixed(conn)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}
	caKeyPEM, err := readLengthPrefixed(conn)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	if p.caCert, err = x509.ParseCertificate(certBlock.Bytes); err != nil {
		return fmt.Errorf("failed to parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	if p.caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}
	return nil
}

func (p *AWSProxy) handleConnect(ctx context.Context, clientConn net.Conn, connectReq *http.Request, l zerolog.Logger) error {
	hostname, port, err := net.SplitHostPort(connectReq.Host)
	if err != nil {
		hostname, port = connectReq.Host, "443"
	}
	if port != "443" || !IsAWSHost(hostname) {
		writeError(clientConn, connectReq, http.StatusBadGateway, fmt.Sprintf("%q is not an AWS API endpoint", connectReq.Host))
		return fmt.Errorf("rejected CONNECT to non-AWS host: %s", connectReq.Host)
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("failed to send CONNECT response: %w", err)
	}

	tlsCert, err := p.generateSignedCert(hostname)
	if err != nil {
		return fmt.Errorf("failed to generate TLS cert for %s: %w", hostname, err)
	}

	tlsConn := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	reader := newRequestReader(tlsConn)
	for {
		req, err := reader.read(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("failed to read HTTP request from TLS: %w", err)
		}

		keepOpen, err := p.handleRequest(ctx, tlsConn, req, hostname, l)
		if err != nil || !keepOpen {
			return err
		}
	}
}

// handleRequest re-signs one request with the session's credentials and relays the response. tunnelHost
// is the host the client tunnelled to, or empty for a plain proxy request that names its target itself.
func (p *AWSProxy) handleRequest(ctx context.Context, w io.Writer, req *http.Request, tunnelHost string, l zerolog.Logger) (bool, error) {
	defer req.Body.Close()

	// Fetched for unsigned requests too, so nothing passes through once Infisical has ended the session
	creds, err := p.config.GetCredentials()
	if err != nil {
		var refusal *RefusalError
		if errors.As(err, &refusal) {
			writeError(w, req, http.StatusForbidden, refusal.Reason)
			return false, nil
		}
		l.Error().Err(err).Msg("Failed to get AWS credentials for session")
		writeError(w, req, http.StatusBadGateway, "failed to get AWS credentials for this session")
		return false, nil
	}

	requestID := uuid.NewString()
	startedAt := time.Now()

	host, err := targetHost(req, tunnelHost)
	if err != nil {
		writeError(w, req, http.StatusBadRequest, err.Error())
		return false, nil
	}

	region, service, signed, err := signingScope(req)
	if err != nil {
		writeError(w, req, http.StatusBadRequest, err.Error())
		return false, nil
	}

	payloadHash := req.Header.Get("X-Amz-Content-Sha256")
	// Each chunk of these carries a signature chained from the client's key, which the gateway can't redo
	if signed && strings.HasPrefix(payloadHash, "STREAMING-") && payloadHash != unsignedPayloadTrailer {
		writeError(w, req, http.StatusBadRequest, "uploads that sign each chunk can't be re-signed by the gateway; upload with an unsigned payload, as the AWS CLI does")
		return false, nil
	}

	// Reserved before the client is told to send the body, so a refusal doesn't cost it the upload
	hashBody := signed && payloadHash == ""
	if hashBody {
		if req.ContentLength > maxHashedBodySize {
			writeError(w, req, http.StatusRequestEntityTooLarge, "request body is too large for the gateway to sign")
			return false, nil
		}
		reserved := int64(maxHashedBodySize)
		if req.ContentLength >= 0 {
			reserved = req.ContentLength
		}
		if !hashedBodies.TryAcquire(reserved) {
			writeError(w, req, http.StatusServiceUnavailable, "the gateway is busy with other large requests; try again shortly")
			return false, nil
		}
		defer hashedBodies.Release(reserved)
	}

	if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
		if _, err := io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return false, err
		}
	}

	var loggedRequestBody bytes.Buffer
	requestBody := &eofReader{r: req.Body}
	var body io.Reader = io.TeeReader(requestBody, &limitedWriter{w: &loggedRequestBody, n: maxLoggedBodySize})
	contentLength := req.ContentLength

	if hashBody {
		buffered, err := io.ReadAll(io.LimitReader(body, maxHashedBodySize+1))
		if err != nil {
			return false, fmt.Errorf("failed to read request body: %w", err)
		}
		if len(buffered) > maxHashedBodySize {
			writeError(w, req, http.StatusRequestEntityTooLarge, "request body is too large for the gateway to sign")
			return false, nil
		}
		sum := sha256.Sum256(buffered)
		payloadHash = hex.EncodeToString(sum[:])
		body = bytes.NewReader(buffered)
		contentLength = int64(len(buffered))
	}

	target := &url.URL{Scheme: "https", Host: host, Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery}
	loggedURL := target.String()

	out, err := http.NewRequestWithContext(ctx, req.Method, loggedURL, body)
	if err != nil {
		writeError(w, req, http.StatusBadRequest, "failed to build the request to AWS")
		return false, nil
	}
	out.URL = target
	out.Host = host
	out.ContentLength = contentLength
	if contentLength == 0 {
		out.Body = http.NoBody
	}
	out.Header = forwardedHeaders(req.Header, signed)

	if signed {
		err = p.signer.SignHTTP(ctx, awssdk.Credentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
		}, out, payloadHash, service, region, time.Now(), func(o *v4.SignerOptions) {
			o.DisableURIPathEscaping = isS3Service(service)
		})
		if err != nil {
			l.Error().Err(err).Msg("Failed to sign AWS request")
			writeError(w, req, http.StatusBadGateway, "failed to sign the request")
			return false, nil
		}
	}

	l.Info().Str("method", req.Method).Str("host", host).Str("service", service).Str("reqId", requestID).Msg("Forwarding AWS request")

	resp, err := p.client.Do(out)

	// Recorded even when the response is lost, since AWS may still have carried out the call
	p.logHttpEvent(session.HttpEvent{
		Timestamp: startedAt,
		RequestId: requestID,
		EventType: session.HttpEventRequest,
		URL:       loggedURL,
		Method:    req.Method,
		Headers:   loggedHeaders(req.Header),
		Body:      loggedRequestBody.Bytes(),
	}, l)

	if err != nil {
		l.Error().Err(err).Str("host", host).Msg("Failed to forward request to AWS")
		writeError(w, req, http.StatusBadGateway, "failed to forward the request to AWS")
		p.logHttpEvent(session.HttpEvent{
			Timestamp: time.Now(),
			RequestId: requestID,
			EventType: session.HttpEventResponse,
			Status:    "502 Bad Gateway",
			Body:      []byte("No response from AWS: " + err.Error()),
		}, l)
		return false, nil
	}
	defer resp.Body.Close()

	var loggedResponseBody bytes.Buffer
	resp.Body = io.NopCloser(io.TeeReader(resp.Body, &limitedWriter{w: &loggedResponseBody, n: maxLoggedBodySize}))
	writeErr := resp.Write(w)

	p.logHttpEvent(session.HttpEvent{
		Timestamp: time.Now(),
		RequestId: requestID,
		EventType: session.HttpEventResponse,
		Status:    resp.Status,
		Headers:   resp.Header,
		Body:      loggedResponseBody.Bytes(),
	}, l)

	if writeErr != nil {
		return false, fmt.Errorf("failed to write response to client: %w", writeErr)
	}

	// Whatever is left of a body AWS didn't read would be parsed as the next request
	return !req.Close && !resp.Close && requestBody.drained(), nil
}

func (p *AWSProxy) logHttpEvent(event session.HttpEvent, l zerolog.Logger) {
	if err := p.config.SessionLogger.LogHttpEvent(event); err != nil {
		l.Error().Err(err).Str("eventType", string(event.EventType)).Msg("Failed to log HTTP event")
	}
}

func (p *AWSProxy) generateSignedCert(hostname string) (tls.Certificate, error) {
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
		NotAfter:     time.Now().Add(25 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, nil
}

func targetHost(req *http.Request, tunnelHost string) (string, error) {
	hostHeader := req.Host
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		hostHeader = h
	}

	if tunnelHost != "" {
		if hostHeader != "" && !strings.EqualFold(hostHeader, tunnelHost) {
			return "", fmt.Errorf("Host %q does not match the tunnelled host %q", hostHeader, tunnelHost)
		}
		return tunnelHost, nil
	}

	if req.URL.Host == "" {
		return "", errors.New("the request names no AWS endpoint")
	}
	if port := req.URL.Port(); port != "" && port != "80" && port != "443" {
		return "", fmt.Errorf("%q is not an AWS API endpoint", req.URL.Host)
	}
	if !IsAWSHost(req.URL.Hostname()) {
		return "", fmt.Errorf("%q is not an AWS API endpoint", req.URL.Host)
	}
	return req.URL.Hostname(), nil
}

// signingScope reads the region and service the client signed the request for. A request the client
// left unsigned, or authorized some other way (an anonymous S3 read, a bearer token), is passed on as it is.
func signingScope(req *http.Request) (region, service string, signed bool, err error) {
	if req.URL.Query().Get("X-Amz-Credential") != "" {
		return "", "", false, errors.New("presigned URLs can't be used through the gateway, because it can't re-sign them")
	}

	auth := req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "AWS4-ECDSA-P256-SHA256") {
		return "", "", false, errors.New("requests signed with SigV4a can't be re-signed by the gateway")
	}
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return "", "", false, nil
	}

	_, scope, found := strings.Cut(auth, "Credential=")
	if !found {
		return "", "", false, errors.New("the request's SigV4 Authorization header has no credential")
	}
	if end := strings.IndexAny(scope, ", "); end >= 0 {
		scope = scope[:end]
	}

	// Credential=<access key>/<date>/<region>/<service>/aws4_request
	parts := strings.Split(scope, "/")
	if len(parts) != 5 || parts[2] == "" || parts[3] == "" || parts[4] != "aws4_request" {
		return "", "", false, errors.New("the request's SigV4 credential scope is malformed")
	}
	return parts[2], parts[3], true, nil
}

// S3 signs the path as sent, where every other service escapes it a second time
func isS3Service(service string) bool {
	switch service {
	case "s3", "s3-object-lambda", "s3-outposts", "s3express":
		return true
	}
	return false
}

// Headers scoped to the client's hop to the gateway. Everything left is signed and sent as is, since the
// signer covers every header on the request.
var hopByHopHeaders = []string{
	"Content-Length", "Expect", "Proxy-Authorization", "Proxy-Connection",
	"Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// The client's signature, which the gateway's replaces.
var clientSignatureHeaders = []string{"Authorization", "X-Amz-Security-Token", "X-Amz-Date"}

func forwardedHeaders(header http.Header, signed bool) http.Header {
	forwarded := header.Clone()
	for _, name := range strings.Split(header.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			forwarded.Del(name)
		}
	}
	for _, name := range hopByHopHeaders {
		forwarded.Del(name)
	}
	if signed {
		for _, name := range clientSignatureHeaders {
			forwarded.Del(name)
		}
	}
	return forwarded
}

// Headers that carry a credential or a key, which the session log would otherwise keep, since it masks only bodies
var credentialHeaders = []string{
	"Authorization", "X-Amz-Security-Token", "Proxy-Authorization", "X-Amz-Sso_bearer_token",
	"X-Amz-Server-Side-Encryption-Customer-Key", "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key",
}

func loggedHeaders(header http.Header) http.Header {
	logged := header.Clone()
	for _, name := range credentialHeaders {
		logged.Del(name)
	}
	return logged
}

var errHeadersTooLarge = errors.New("request line and headers exceed the size limit")

// headerLimit caps the bytes read while a request's line and headers are parsed, as http.Server's
// MaxHeaderBytes does, since http.ReadRequest alone would buffer a header that never ends
type headerLimit struct {
	r io.Reader
	n int64
}

func (h *headerLimit) Read(p []byte) (int, error) {
	if h.n <= 0 {
		return 0, errHeadersTooLarge
	}
	if int64(len(p)) > h.n {
		p = p[:h.n]
	}
	n, err := h.r.Read(p)
	h.n -= int64(n)
	return n, err
}

type requestReader struct {
	limit  *headerLimit
	reader *bufio.Reader
}

func newRequestReader(conn io.Reader) *requestReader {
	limit := &headerLimit{r: conn}
	return &requestReader{limit: limit, reader: bufio.NewReader(limit)}
}

func (r *requestReader) read(ctx context.Context) (*http.Request, error) {
	// bufio reads ahead of the headers, so the cap leaves room for a full buffer
	r.limit.n = http.DefaultMaxHeaderBytes + int64(r.reader.Size())

	type result struct {
		req *http.Request
		err error
	}
	ch := make(chan result, 1)
	go func() {
		req, err := http.ReadRequest(r.reader)
		ch <- result{req, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err == nil {
			r.limit.n = math.MaxInt64
		}
		return res.req, res.err
	}
}

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

const gatewayErrorCode = "InfisicalGatewayError"

// writeError answers in the format the client's AWS SDK parses errors in, so it shows the message rather than
// a bare status. JSON services send X-Amz-Target or a JSON body; S3, STS, EC2 and the rest expect XML.
func writeError(w io.Writer, req *http.Request, status int, message string) {
	contentType := "text/xml"
	var body []byte
	if req.Header.Get("X-Amz-Target") != "" || strings.Contains(req.Header.Get("Content-Type"), "json") {
		contentType = "application/json"
		body, _ = json.Marshal(map[string]string{"__type": gatewayErrorCode, "message": message})
	} else {
		var escaped bytes.Buffer
		_ = xml.EscapeText(&escaped, []byte(message))
		body = []byte("<ErrorResponse><Error><Code>" + gatewayErrorCode + "</Code><Message>" + escaped.String() + "</Message></Error></ErrorResponse>")
	}
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nX-Amzn-ErrorType: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), contentType, gatewayErrorCode, len(body), body)
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.n <= 0 {
		return len(p), nil
	}
	chunk := p
	if len(chunk) > lw.n {
		chunk = chunk[:lw.n]
	}
	n, err := lw.w.Write(chunk)
	lw.n -= n
	if err != nil {
		return n, err
	}
	return len(p), nil
}

// eofReader records whether the body was read to its end, so the connection is only reused when the
// next request starts where this one finished.
type eofReader struct {
	r   io.Reader
	eof bool
}

func (e *eofReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if errors.Is(err, io.EOF) {
		e.eof = true
	}
	return n, err
}

func (e *eofReader) drained() bool {
	if e.eof {
		return true
	}
	// AWS answered without reading a short remainder, such as an empty body it never asked for
	_, err := io.Copy(io.Discard, io.LimitReader(e, 64<<10))
	return err == nil && e.eof
}
