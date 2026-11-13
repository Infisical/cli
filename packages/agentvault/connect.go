package agentvault

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	connectDialTimeout = 10 * time.Second
	// Longer than the proxy's own wait on Infisical (controlPlaneTimeout), so a slow first lookup of a session comes
	// back as the proxy's answer rather than a timeout here.
	connectResponseTimeout = 30 * time.Second
	// The longest a CONNECT host label can be, so a longer service name can never be reached.
	maxNativeServiceNameLength = 63
	connectAcceptBackoffMax    = time.Second
	nativeServicesResponseCap  = 1 << 20
)

// ErrProxyTooOld means the proxy at the address answers, but predates database and SSH services.
var ErrProxyTooOld = errors.New("the Agent Vault proxy at this address is too old to serve database and SSH services; update it to the latest Infisical CLI")

// ProxyRefusedError is the proxy's own refusal, whose message is written for the person reading it.
type ProxyRefusedError struct {
	Status int
	// The proxy's error code (HeaderError), such as a session it can't use; empty from a proxy too old to send one.
	Code    string
	Message string
}

func (e *ProxyRefusedError) Error() string { return e.Message }

const sessionInvalidRefusal = "the session is no longer valid, or it belongs to a different Agent Vault project than this proxy"

const notOnPlanRefusal = "Agent Vault isn't on this organization's plan"

// SessionInvalid is true when the proxy refused because the session itself can't be used any more. A service refusal
// is the same 403, so the code tells them apart.
func (e *ProxyRefusedError) SessionInvalid() bool {
	return e.Status == http.StatusForbidden && e.Code == errorCodeSessionInvalid
}

// LocalConnError is a failure on this machine's side of a tunnel, such as the local client resetting its
// connection, as opposed to one between here and the proxy.
type LocalConnError struct {
	Err error
}

func (e *LocalConnError) Error() string { return e.Err.Error() }
func (e *LocalConnError) Unwrap() error { return e.Err }

// ConnectClient talks to the proxy's TLS door for `infisical agent-vault connect`. RootCAs holds only the proxy's
// own CA, which the caller has already pinned, so the session token never goes to anything else.
type ConnectClient struct {
	ProxyAddr    string
	SessionToken string
	RootCAs      *x509.CertPool
}

func (c *ConnectClient) dial(ctx context.Context) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: connectDialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", c.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("could not reach the Agent Vault proxy at %s: %w", c.ProxyAddr, err)
	}
	conn := tls.Client(raw, &tls.Config{
		RootCAs:    c.RootCAs,
		ServerName: ProxyTLSServerName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	_ = conn.SetDeadline(time.Now().Add(connectDialTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		// An older proxy reads the handshake as a bad HTTP request and answers in plain text.
		var notTLS tls.RecordHeaderError
		if errors.As(err, &notTLS) {
			return nil, ErrProxyTooOld
		}
		return nil, fmt.Errorf("could not open a secure connection to the Agent Vault proxy at %s: %w", c.ProxyAddr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (c *ConnectClient) proxyAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername+":"+c.SessionToken))
}

// ListNativeServices asks the proxy which database and SSH services the session has.
func (c *ConnectClient) ListNativeServices(ctx context.Context) ([]NativeServiceInfo, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(connectResponseTimeout))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ProxyTLSServerName+NativeServicesPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Proxy-Authorization", c.proxyAuthorization())
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, fmt.Errorf("the Agent Vault proxy didn't answer the service list request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, refusalOf(resp)
	}
	var out NativeServicesResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, nativeServicesResponseCap)).Decode(&out); err != nil {
		return nil, fmt.Errorf("the Agent Vault proxy's service list could not be read: %w", err)
	}
	return out.Services, nil
}

// Probe checks the proxy would serve the service, without opening a connection to it.
func (c *ConnectClient) Probe(ctx context.Context, service string) error {
	conn, err := c.connect(ctx, service, true)
	if err != nil {
		return err
	}
	return conn.Close()
}

// OpenTunnel opens a tunnel to the service; what is written to it reaches the service's server.
func (c *ConnectClient) OpenTunnel(ctx context.Context, service string) (net.Conn, error) {
	return c.connect(ctx, service, false)
}

func (c *ConnectClient) connect(ctx context.Context, service string, probe bool) (net.Conn, error) {
	if len(service) > maxNativeServiceNameLength {
		return nil, fmt.Errorf("%q is longer than any database or SSH service name can be", service)
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(connectResponseTimeout))

	target := net.JoinHostPort(strings.ToLower(service)+NativeServiceSuffix, NativeServicePort)
	probeHeader := ""
	if probe {
		probeHeader = NativeProbeHeader + ": 1\r\n"
	}
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n%s\r\n", target, target, c.proxyAuthorization(), probeHeader)
	if _, err := io.WriteString(conn, request); err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("the Agent Vault proxy didn't answer the tunnel request: %w", err)
	}

	switch {
	case probe && resp.StatusCode == http.StatusNoContent:
		return conn, nil
	case !probe && resp.StatusCode == http.StatusOK:
		_ = conn.SetDeadline(time.Time{})
		// The server can speak right behind the 200 (an SSH or MySQL server does), so what was buffered is kept.
		return &readerConn{Conn: conn, reader: reader}, nil
	}
	defer conn.Close()
	return nil, refusalOf(resp)
}

func refusalOf(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	message := strings.TrimSpace(string(body))
	// The proxy's refusal carries its text in a JSON body; a proxy too old to send one wrote the text itself.
	var coded proxyErrorBody
	if json.Unmarshal(body, &coded) == nil && coded.Message != "" {
		message = coded.Message
	}
	if message == "" {
		message = fmt.Sprintf("the Agent Vault proxy refused the request (%d)", resp.StatusCode)
	}
	return &ProxyRefusedError{Status: resp.StatusCode, Code: resp.Header.Get(HeaderError), Message: message}
}

// waitsForClient is true for protocols whose client speaks first. For those a port check that connects and says
// nothing must not make the proxy log in to the server, so the tunnel opens only once the client sends a byte.
func waitsForClient(serviceType string) bool {
	return serviceType == serviceKindPostgres || serviceType == serviceKindSSH
}

// ServeLocal accepts local connections on ln and tunnels each to the service until ctx ends. The bytes are never
// read here beyond the first: the client speaks its own protocol, and the proxy logs in with the service's account.
func (c *ConnectClient) ServeLocal(ctx context.Context, ln net.Listener, service NativeServiceInfo, onError func(error)) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	backoff := 5 * time.Millisecond
	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// A full file table and the like pass; give them a moment rather than spinning or giving up.
			onError(&LocalConnError{Err: err})
			time.Sleep(backoff)
			backoff = min(2*backoff, connectAcceptBackoffMax)
			continue
		}
		backoff = 5 * time.Millisecond
		go func() {
			defer local.Close()
			if err := c.tunnel(ctx, local, service); err != nil {
				onError(err)
			}
		}()
	}
}

func (c *ConnectClient) tunnel(ctx context.Context, local net.Conn, service NativeServiceInfo) error {
	// Set before the first-byte read below, so a client that connects and stays silent is still closed on cancel.
	stopLocal := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer stopLocal()

	var first []byte
	if waitsForClient(service.Type) {
		buf := make([]byte, 1)
		n, err := local.Read(buf)
		if n == 0 {
			if err == nil || errors.Is(err, io.EOF) {
				return nil
			}
			return &LocalConnError{Err: err}
		}
		first = buf[:n]
	}

	upstream, err := c.OpenTunnel(ctx, service.Name)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if len(first) > 0 {
		if _, err := upstream.Write(first); err != nil {
			return err
		}
	}

	// Closing either side ends the other, so a client that never closes doesn't keep a dead tunnel open.
	stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, local)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, upstream)
		// The server is done, so the client is too; its half-close alone would leave a client that never closes.
		_ = local.Close()
	}()
	wg.Wait()
	return nil
}

type readerConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func closeWrite(c net.Conn) {
	if rc, ok := c.(*readerConn); ok {
		c = rc.Conn
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
