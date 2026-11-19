package aws

import (
	"bufio"
	"context"
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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

var (
	clientCreds  = awssdk.Credentials{AccessKeyID: "infisical-pam-proxy-managed", SecretAccessKey: "infisical-pam-proxy-managed"}
	sessionCreds = Credentials{AccessKeyID: "ASIAREALKEY", SecretAccessKey: "real-secret", SessionToken: "real-session-token"}
)

func TestIsAWSHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"sts.amazonaws.com", true},
		{"s3.us-east-1.amazonaws.com:443", true},
		{"my-bucket.s3.eu-west-1.amazonaws.com", true},
		{"ec2.cn-north-1.amazonaws.com.cn", true},
		{"s3.dualstack.us-east-1.api.aws", true},
		{"STS.AMAZONAWS.COM", true},

		{"evil.com", false},
		{"evil.com#.amazonaws.com", false},
		{"evil.com?.amazonaws.com", false},
		{"evil.com/.amazonaws.com", false},
		{"evil.com\\.amazonaws.com", false},
		{"user@sts.amazonaws.com", false},
		{"notamazonaws.com", false},
		{"amazonaws.com.evil.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsAWSHost(tt.host); got != tt.want {
				t.Errorf("IsAWSHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestSigningScope(t *testing.T) {
	request := func(target, auth string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return req
	}

	region, service, signed, err := signingScope(request("/", "AWS4-HMAC-SHA256 Credential=AKID/20261116/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc"))
	if err != nil || !signed || region != "eu-west-1" || service != "s3" {
		t.Fatalf("got region=%q service=%q signed=%v err=%v", region, service, signed, err)
	}

	if _, _, signed, err := signingScope(request("/", "")); err != nil || signed {
		t.Fatalf("an unsigned request should pass through unsigned, got signed=%v err=%v", signed, err)
	}
	if _, _, signed, err := signingScope(request("/", "Bearer token")); err != nil || signed {
		t.Fatalf("a request with its own token should pass through, got signed=%v err=%v", signed, err)
	}

	for name, req := range map[string]*http.Request{
		"presigned": request("/key?X-Amz-Credential=AKID%2F20261116%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=abc", ""),
		"sigv4a":    request("/", "AWS4-ECDSA-P256-SHA256 Credential=AKID/20261116/s3/aws4_request, SignedHeaders=host, Signature=abc"),
		"malformed": request("/", "AWS4-HMAC-SHA256 Credential=AKID/20261116/us-east-1, SignedHeaders=host, Signature=abc"),
	} {
		if _, _, _, err := signingScope(req); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

type recordedRequest struct {
	req  *http.Request
	body []byte
	err  error
}

// fakeAWS checks each request's signature against the session's credentials, the way AWS would.
func fakeAWS(t *testing.T) (*httptest.Server, <-chan recordedRequest) {
	t.Helper()
	received := make(chan recordedRequest, 10)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- recordedRequest{req: r, body: body, err: verifySignature(r, body)}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok from aws"))
	}))
	t.Cleanup(server.Close)
	return server, received
}

func verifySignature(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil
	}

	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ", ") {
		key, value, _ := strings.Cut(part, "=")
		fields[key] = value
	}
	scope := strings.Split(fields["Credential"], "/")
	if scope[0] != sessionCreds.AccessKeyID {
		return errMismatch("access key " + scope[0])
	}

	signingTime, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return err
	}

	rebuilt := r.Clone(context.Background())
	rebuilt.URL.Scheme, rebuilt.URL.Host = "https", r.Host
	rebuilt.Header = http.Header{}
	rebuilt.ContentLength = 0
	for _, name := range strings.Split(fields["SignedHeaders"], ";") {
		switch name {
		case "host":
		case "content-length":
			rebuilt.ContentLength = r.ContentLength
		default:
			rebuilt.Header[http.CanonicalHeaderKey(name)] = r.Header.Values(name)
		}
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}

	err = v4.NewSigner().SignHTTP(context.Background(), awssdk.Credentials{
		AccessKeyID:     sessionCreds.AccessKeyID,
		SecretAccessKey: sessionCreds.SecretAccessKey,
		SessionToken:    sessionCreds.SessionToken,
	}, rebuilt, payloadHash, scope[3], scope[2], signingTime, func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = isS3Service(scope[3])
	})
	if err != nil {
		return err
	}
	if rebuilt.Header.Get("Authorization") != auth {
		return errMismatch("signature")
	}
	return nil
}

type errMismatch string

func (e errMismatch) Error() string { return "mismatched " + string(e) }

type recordingLogger struct {
	mu     sync.Mutex
	events []session.HttpEvent
}

func (r *recordingLogger) LogEntry(session.SessionLogEntry) error     { return nil }
func (r *recordingLogger) LogSessionEvent(session.SessionEvent) error { return nil }
func (r *recordingLogger) Close() error                               { return nil }
func (r *recordingLogger) LogHttpEvent(event session.HttpEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *recordingLogger) waitFor(t *testing.T, count int) []session.HttpEvent {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		events := append([]session.HttpEvent(nil), r.events...)
		r.mu.Unlock()
		if len(events) >= count || time.Now().After(deadline) {
			if len(events) != count {
				t.Fatalf("logged %d events, want %d", len(events), count)
			}
			return events
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newTestCA(t *testing.T) (certPEM, keyPEM []byte, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pool
}

func writeLengthPrefixed(t *testing.T, w io.Writer, data []byte) {
	t.Helper()
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))
	if _, err := w.Write(append(length, data...)); err != nil {
		t.Fatal(err)
	}
}

// startProxy runs a proxy against fake AWS and returns the client end of its connection, with the CA sent.
func startProxy(t *testing.T, server *httptest.Server) (net.Conn, *x509.CertPool, *recordingLogger) {
	t.Helper()
	return startProxyWith(t, server, func() (Credentials, error) { return sessionCreds, nil })
}

func startProxyWith(t *testing.T, server *httptest.Server, getCredentials func() (Credentials, error)) (net.Conn, *x509.CertPool, *recordingLogger) {
	t.Helper()
	logger := &recordingLogger{}
	proxy := NewAWSProxy(AWSProxyConfig{
		SessionID:      "test-session",
		SessionLogger:  logger,
		GetCredentials: getCredentials,
	})
	proxy.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		TLSNextProto:       make(map[string]func(string, *tls.Conn) http.RoundTripper),
		DisableCompression: true,
	}

	clientConn, gatewayConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = proxy.HandleConnection(ctx, gatewayConn)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		clientConn.Close()
		<-done
	})

	certPEM, keyPEM, pool := newTestCA(t)
	writeLengthPrefixed(t, clientConn, certPEM)
	writeLengthPrefixed(t, clientConn, keyPEM)
	return clientConn, pool, logger
}

func connect(t *testing.T, conn net.Conn, pool *x509.CertPool, host string) *tls.Conn {
	t.Helper()
	if _, err := io.WriteString(conn, "CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with the gateway failed: %v", err)
	}
	return tlsConn
}

func signedRequest(t *testing.T, method, url, service, region, payloadHash string, body string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if payloadHash == "" {
		sum := sha256.Sum256([]byte(body))
		payloadHash = hex.EncodeToString(sum[:])
	} else {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}
	err = v4.NewSigner().SignHTTP(context.Background(), clientCreds, req, payloadHash, service, region, time.Now(), func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = isS3Service(service)
	})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func roundTrip(t *testing.T, conn net.Conn, reader *bufio.Reader, req *http.Request) *http.Response {
	t.Helper()
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	return resp
}

func TestProxyResignsRequestsWithSessionCredentials(t *testing.T) {
	server, received := fakeAWS(t)
	conn, pool, logger := startProxy(t, server)

	const host = "my-bucket.s3.us-east-1.amazonaws.com"
	tlsConn := connect(t, conn, pool, host)
	reader := bufio.NewReader(tlsConn)

	// S3 signs the path as sent, so a key needing escapes catches a path the gateway altered
	s3Put := signedRequest(t, http.MethodPut, "https://"+host+"/reports/q3%20final+v2~%C3%BC.txt?x-id=PutObject",
		"s3", "us-east-1", "UNSIGNED-PAYLOAD", "hello", map[string]string{"Content-Type": "text/plain"})
	if resp := roundTrip(t, tlsConn, reader, s3Put); resp.StatusCode != http.StatusOK {
		t.Fatalf("S3 PUT status = %d", resp.StatusCode)
	}

	got := <-received
	if got.err != nil {
		t.Fatalf("AWS rejected the S3 signature: %v", got.err)
	}
	if got.req.Header.Get("X-Amz-Security-Token") != sessionCreds.SessionToken {
		t.Errorf("session token = %q", got.req.Header.Get("X-Amz-Security-Token"))
	}
	if got.req.URL.EscapedPath() != "/reports/q3%20final+v2~%C3%BC.txt" {
		t.Errorf("path = %q", got.req.URL.EscapedPath())
	}
	if string(got.body) != "hello" {
		t.Errorf("body = %q", got.body)
	}

	// A JSON service sends no payload hash, so the gateway hashes the body itself; the same tunnel is reused
	dynamo := signedRequest(t, http.MethodPost, "https://"+host+"/", "dynamodb", "us-east-1", "",
		`{"TableName":"t"}`, map[string]string{"X-Amz-Target": "DynamoDB_20120810.DescribeTable", "Content-Type": "application/x-amz-json-1.0"})
	if resp := roundTrip(t, tlsConn, reader, dynamo); resp.StatusCode != http.StatusOK {
		t.Fatalf("DynamoDB status = %d", resp.StatusCode)
	}
	if got := <-received; got.err != nil {
		t.Fatalf("AWS rejected the DynamoDB signature: %v", got.err)
	}

	// The response is logged once it has been relayed, so it can land just after the client reads it
	events := logger.waitFor(t, 4)
	for _, event := range events {
		if event.Headers.Get("Authorization") != "" || event.Headers.Get("X-Amz-Security-Token") != "" {
			t.Errorf("%s event logged credentials", event.EventType)
		}
	}
	if string(events[1].Body) != "ok from aws" {
		t.Errorf("logged response body = %q", events[1].Body)
	}
}

func TestProxyPassesUnsignedRequestsThrough(t *testing.T) {
	server, received := fakeAWS(t)
	conn, pool, logger := startProxy(t, server)

	const host = "portal.sso.us-east-1.amazonaws.com"
	tlsConn := connect(t, conn, pool, host)

	req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/assignment/accounts", nil)
	req.Header.Set("x-amz-sso_bearer_token", "sso-access-token")
	if resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), req); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got := <-received
	if got.req.Header.Get("Authorization") != "" || got.req.Header.Get("X-Amz-Security-Token") != "" {
		t.Fatal("the gateway signed a request the client left unsigned")
	}
	if got.req.Header.Get("x-amz-sso_bearer_token") != "sso-access-token" {
		t.Error("the SSO token didn't reach AWS")
	}
	if logged := logger.waitFor(t, 2)[0].Headers.Get("x-amz-sso_bearer_token"); logged != "" {
		t.Errorf("the session log kept the SSO token %q", logged)
	}
}

func TestProxyRecordsCallsWhoseResponseIsLost(t *testing.T) {
	server, _ := fakeAWS(t)
	conn, pool, logger := startProxy(t, server)
	server.Close()

	const host = "sts.amazonaws.com"
	tlsConn := connect(t, conn, pool, host)
	req := signedRequest(t, http.MethodPost, "https://"+host+"/", "sts", "us-east-1", "",
		"Action=GetCallerIdentity&Version=2011-06-15", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), req); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	events := logger.waitFor(t, 2)
	if events[0].EventType != session.HttpEventRequest || string(events[0].Body) != "Action=GetCallerIdentity&Version=2011-06-15" {
		t.Errorf("request event = %s %q", events[0].EventType, events[0].Body)
	}
	if events[1].EventType != session.HttpEventResponse || events[1].Status != "502 Bad Gateway" {
		t.Errorf("response event = %s %q", events[1].EventType, events[1].Status)
	}
}

func TestProxyRefusesWhatItCannotSign(t *testing.T) {
	server, received := fakeAWS(t)

	t.Run("presigned URL", func(t *testing.T) {
		conn, pool, _ := startProxy(t, server)
		const host = "s3.amazonaws.com"
		tlsConn := connect(t, conn, pool, host)
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/b/k?X-Amz-Credential=AKID%2F20261116%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=abc", nil)
		if resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), req); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("chunk-signed upload", func(t *testing.T) {
		conn, pool, _ := startProxy(t, server)
		const host = "s3.amazonaws.com"
		tlsConn := connect(t, conn, pool, host)
		req := signedRequest(t, http.MethodPut, "https://"+host+"/b/k", "s3", "us-east-1", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "x", nil)
		if resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), req); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("host outside AWS", func(t *testing.T) {
		conn, _, _ := startProxy(t, server)
		if _, err := io.WriteString(conn, "CONNECT internal.example.com:443 HTTP/1.1\r\nHost: internal.example.com:443\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", resp.StatusCode)
		}
	})

	select {
	case got := <-received:
		t.Fatalf("a refused request reached AWS: %s %s", got.req.Method, got.req.URL)
	default:
	}
}

func TestProxyShowsWhyInfisicalRefusedTheSession(t *testing.T) {
	server, received := fakeAWS(t)
	refused := func() (Credentials, error) { return Credentials{}, &RefusalError{Reason: "Session is not active"} }

	t.Run("XML service", func(t *testing.T) {
		conn, pool, _ := startProxyWith(t, server, refused)
		const host = "s3.amazonaws.com"
		tlsConn := connect(t, conn, pool, host)
		req := signedRequest(t, http.MethodGet, "https://"+host+"/", "s3", "us-east-1", "UNSIGNED-PAYLOAD", "", nil)
		resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), req)
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "<Code>InfisicalGatewayError</Code><Message>Session is not active</Message>") {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
		}
	})

	t.Run("JSON service", func(t *testing.T) {
		conn, pool, _ := startProxyWith(t, server, refused)
		const host = "dynamodb.us-east-1.amazonaws.com"
		tlsConn := connect(t, conn, pool, host)
		req := signedRequest(t, http.MethodPost, "https://"+host+"/", "dynamodb", "us-east-1", "",
			`{"TableName":"t"}`, map[string]string{"X-Amz-Target": "DynamoDB_20120810.DescribeTable", "Content-Type": "application/x-amz-json-1.0"})
		resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), req)
		var parsed map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden || parsed["__type"] != "InfisicalGatewayError" || parsed["message"] != "Session is not active" {
			t.Fatalf("status = %d, body = %v", resp.StatusCode, parsed)
		}
	})

	t.Run("unsigned request", func(t *testing.T) {
		conn, pool, _ := startProxyWith(t, server, refused)
		const host = "public-bucket.s3.amazonaws.com"
		tlsConn := connect(t, conn, pool, host)
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/object", nil)
		if resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), req); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})

	select {
	case got := <-received:
		t.Fatalf("a request for a refused session reached AWS: %s %s", got.req.Method, got.req.URL)
	default:
	}
}

func TestProxyCapsRequestHeaders(t *testing.T) {
	server, received := fakeAWS(t)
	conn, pool, _ := startProxy(t, server)
	const host = "s3.amazonaws.com"
	tlsConn := connect(t, conn, pool, host)
	// The pipe has no buffer, so the gateway's close-notify would wait out its timeout unless something reads it
	go func() { _, _ = io.Copy(io.Discard, tlsConn) }()

	header := "GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Padding: " + strings.Repeat("a", 2*http.DefaultMaxHeaderBytes) + "\r\n\r\n"
	if _, err := io.WriteString(tlsConn, header); err == nil {
		t.Fatal("the gateway read a header twice the size limit to its end")
	}

	select {
	case got := <-received:
		t.Fatalf("a request with oversized headers reached AWS: %s %s", got.req.Method, got.req.URL)
	default:
	}
}

func TestProxyLimitsMemoryForBodiesItHashes(t *testing.T) {
	server, received := fakeAWS(t)
	const host = "dynamodb.us-east-1.amazonaws.com"
	describeTable := func() *http.Request {
		return signedRequest(t, http.MethodPost, "https://"+host+"/", "dynamodb", "us-east-1", "",
			`{"TableName":"t"}`, map[string]string{"X-Amz-Target": "DynamoDB_20120810.DescribeTable", "Content-Type": "application/x-amz-json-1.0"})
	}

	if !hashedBodies.TryAcquire(2 * maxHashedBodySize) {
		t.Fatal("the shared budget is already in use")
	}
	conn, pool, _ := startProxy(t, server)
	tlsConn := connect(t, conn, pool, host)
	resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), describeTable())
	hashedBodies.Release(2 * maxHashedBodySize)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status with the budget used up = %d, want 503", resp.StatusCode)
	}

	conn, pool, _ = startProxy(t, server)
	tlsConn = connect(t, conn, pool, host)
	if resp := roundTrip(t, tlsConn, bufio.NewReader(tlsConn), describeTable()); resp.StatusCode != http.StatusOK {
		t.Fatalf("status once the budget is free = %d", resp.StatusCode)
	}
	if got := <-received; got.err != nil {
		t.Fatalf("AWS rejected the signature: %v", got.err)
	}

	// Refused from its declared length, before the client sends any of it
	conn, pool, _ = startProxy(t, server)
	tlsConn = connect(t, conn, pool, host)
	oversized := "POST / HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Authorization: AWS4-HMAC-SHA256 Credential=AKID/20261118/us-east-1/dynamodb/aws4_request, SignedHeaders=host, Signature=abc\r\n" +
		"Content-Length: " + strconv.Itoa(maxHashedBodySize+1) + "\r\n\r\n"
	if _, err := io.WriteString(tlsConn, oversized); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status for an oversized body = %d, want 413", resp.StatusCode)
	}
}
