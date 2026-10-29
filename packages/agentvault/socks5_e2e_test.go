package agentvault

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var testSocks5Token = "agv_" + strings.Repeat("t", 43)

type socks5Fixture struct {
	ps       *proxyServer
	addr     string
	proxyCAs *x509.CertPool
	server   *socks5Server
	upstream *httptest.Server
	hits     *atomic.Int64
}

// A proxy whose SOCKS5 port is served over TLS with a certificate minted for 127.0.0.1, in front of an
// echoing TLS upstream on 127.0.0.1. Both upstream transports trust the upstream's certificate.
func newSocks5Fixture(t *testing.T, resolver sessionResolver, configure func(*proxyServer, *Socks5Options, *socks5Server)) *socks5Fixture {
	t.Helper()

	hits := &atomic.Int64{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"method":%q,"path":%q,"headers":{"X-Injected":[%q]}}`, r.Method, r.URL.Path, r.Header.Get("X-Injected"))
	}))
	t.Cleanup(upstream.Close)
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	transport := newUpstreamTransport()
	transport.TLSClientConfig = &tls.Config{RootCAs: upstreamPool}
	guarded := newGuardedUpstreamTransport()
	guarded.TLSClientConfig = &tls.Config{RootCAs: upstreamPool}

	ps := &proxyServer{transport: transport, guardedTransport: guarded, ca: newCaManager(key, cert)}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(resolver, ps.pollInterval)

	opts := &Socks5Options{TLSName: "127.0.0.1"}
	server := newSocks5Server(ps, nil)
	server.stepTimeout = 2 * time.Second
	if configure != nil {
		configure(ps, opts, server)
	}
	server.tlsConfig = socks5TLSConfig(ps.ca, opts)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.serve(raw) }()
	t.Cleanup(func() {
		_ = raw.Close()
		<-done
		server.wait()
	})

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &socks5Fixture{ps: ps, addr: raw.Addr().String(), proxyCAs: pool, server: server, upstream: upstream, hits: hits}
}

func (f *socks5Fixture) upstreamPort(t *testing.T) uint16 {
	t.Helper()
	u, err := url.Parse(f.upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return uint16(port)
}

// dialSocks5 does what E2B's host does: TLS to the proxy, then the SOCKS5 greeting, login and CONNECT. It
// returns the reply codes so a test can check a refusal, and the connection when the tunnel opened.
func dialSocks5(t *testing.T, addr string, outer *tls.Config, user, password, host string, port uint16) (net.Conn, byte, byte) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, outer)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	frame := []byte{5, 1, socks5MethodUserPass}
	frame = append(frame, 1, byte(len(user)))
	frame = append(frame, user...)
	frame = append(frame, byte(len(password)))
	frame = append(frame, password...)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		t.Fatalf("no method selection: %v", err)
	}
	var auth [2]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil {
		conn.Close()
		return nil, 0xff, 0
	}
	if auth[1] != socks5AuthStatusOK {
		conn.Close()
		return nil, auth[1], 0
	}

	req := []byte{5, socks5CmdConnect, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, socks5AtypIPv4)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, socks5AtypDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("no reply: %v", err)
	}
	if reply[1] != socks5RepSucceeded {
		conn.Close()
		return nil, auth[1], reply[1]
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, auth[1], reply[1]
}

func (f *socks5Fixture) outerTLS() *tls.Config {
	return &tls.Config{RootCAs: f.proxyCAs, ServerName: "127.0.0.1"}
}

// get sends one HTTPS request through a SOCKS5 tunnel to host:port and returns the status and body.
func (f *socks5Fixture) get(t *testing.T, host string, port uint16) (int, string) {
	t.Helper()
	conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, host, port)
	if conn == nil {
		t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
	}
	defer conn.Close()
	inner := tls.Client(conn, &tls.Config{RootCAs: f.proxyCAs, ServerName: host})
	req, _ := http.NewRequest(http.MethodGet, "https://"+net.JoinHostPort(host, strconv.Itoa(int(port)))+"/x", nil)
	if err := req.Write(inner); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(inner), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func bearerService(host string) *resolvedService {
	return &resolvedService{
		name:             "api",
		accessBundleName: "bundle",
		hostPatterns:     parseHostPatterns(host),
		credential:       credential{kind: credentialBearer, headerName: "X-Injected", value: []byte("s3cr3t")},
	}
}

func TestSocks5BrokersARequestOverTLS(t *testing.T) {
	var f *socks5Fixture
	f = newSocks5Fixture(t, resolverFunc(func() (*resolveResult, error) {
		return &resolveResult{SessionID: "s1", Services: []*resolvedService{bearerService("127.0.0.1:" + strconv.Itoa(int(f.upstreamPort(t))))}}, nil
	}), nil)

	status, body := f.get(t, "127.0.0.1", f.upstreamPort(t))
	if status != http.StatusOK || !strings.Contains(body, "s3cr3t") {
		t.Fatalf("status=%d body=%s, want the injected credential echoed", status, body)
	}
}

func TestSocks5ServesTheOperatorsOwnCertificate(t *testing.T) {
	certPEM, keyPEM, pool := selfSignedListenerCert(t, "127.0.0.1", time.Now().Add(time.Hour))
	own, err := LoadListenerCert(OwnCaInput{Cert: certPEM, CertSource: "--socks5-tls-cert", Key: keyPEM, KeySource: "--socks5-tls-key"})
	if err != nil {
		t.Fatal(err)
	}
	var f *socks5Fixture
	f = newSocks5Fixture(t, resolverFunc(func() (*resolveResult, error) {
		return &resolveResult{SessionID: "s1", Services: []*resolvedService{bearerService("127.0.0.1:" + strconv.Itoa(int(f.upstreamPort(t))))}}, nil
	}), func(_ *proxyServer, opts *Socks5Options, _ *socks5Server) { opts.Cert = own })

	conn, auth, rep := dialSocks5(t, f.addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}, "", testSocks5Token, "127.0.0.1", f.upstreamPort(t))
	if conn == nil {
		t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
	}
	conn.Close()
}

func TestLoadListenerCertRefusesAnExpiredCertificate(t *testing.T) {
	certPEM, keyPEM, _ := selfSignedListenerCert(t, "proxy.example.com", time.Now().Add(-time.Minute))
	_, err := LoadListenerCert(OwnCaInput{Cert: certPEM, CertSource: "--socks5-tls-cert", Key: keyPEM, KeySource: "--socks5-tls-key"})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want an expiry error", err)
	}
}

func TestSocks5RefusesAtLogin(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		msg  string
	}{
		{"revoked or expired session", &api.APIError{StatusCode: 401, Name: infisicalUnauthorizedName}, "the session is no longer valid"},
		{"proxy token rejected", &api.APIError{StatusCode: 401, Name: proxyTokenRejectedName}, "Infisical rejected this proxy's token"},
		{"Infisical unreachable", errors.New("dial tcp: connection refused"), "the session could not be resolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			restore := log.Logger
			log.Logger = zerolog.New(&syncWriter{w: &logs})
			t.Cleanup(func() { log.Logger = restore })

			f := newSocks5Fixture(t, &stubResolver{err: tc.err}, nil)
			conn, auth, _ := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", 443)
			if conn != nil || auth != socks5AuthStatusRefus {
				t.Fatalf("auth = %#x, want the login refused", auth)
			}
			f.server.wait()
			out := logs.String()
			if !strings.Contains(out, tc.msg) || !strings.Contains(out, `"door":"socks5"`) || !strings.Contains(out, `"remote":`) {
				t.Fatalf("refusal not logged as expected: %s", out)
			}
			if strings.Contains(out, testSocks5Token) {
				t.Fatal("the session token reached the log")
			}
		})
	}
}

func TestSocks5JunkPasswordNeverAsksInfisical(t *testing.T) {
	resolver := &stubResolver{result: &resolveResult{SessionID: "s1"}}
	f := newSocks5Fixture(t, resolver, nil)
	for _, password := range []string{"", "hunter2", testSocks5Token + "\n"} {
		conn, auth, _ := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, password, "127.0.0.1", 443)
		if conn != nil || auth != socks5AuthStatusRefus {
			t.Fatalf("password %q: auth = %#x, want refused", password, auth)
		}
	}
	if n := resolver.callCount(); n != 0 {
		t.Fatalf("Infisical was asked %d times about passwords that are not session tokens", n)
	}
}

func TestSocks5AcceptsAnEmptyUsername(t *testing.T) {
	f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, nil)
	conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), "", testSocks5Token, "127.0.0.1", 443)
	if conn == nil {
		t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
	}
	conn.Close()
}

func TestSocks5SessionRevokedMidTunnelGets403(t *testing.T) {
	f := newSocks5Fixture(t, expiringResolver{ttl: 300 * time.Millisecond}, func(ps *proxyServer, _ *Socks5Options, _ *socks5Server) {
		ps.socks5AllowPrivate = true
	})
	conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", f.upstreamPort(t))
	if conn == nil {
		t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
	}
	defer conn.Close()
	time.Sleep(400 * time.Millisecond)

	inner := tls.Client(conn, &tls.Config{RootCAs: f.proxyCAs, ServerName: "127.0.0.1"})
	req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1/x", nil)
	if err := req.Write(inner); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(inner), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "no longer valid") {
		t.Fatalf("status=%d body=%s, want 403 session no longer valid", resp.StatusCode, body)
	}
}

func TestSocks5PrivateDestinations(t *testing.T) {
	t.Run("any-host: a host no service names that resolves to loopback is refused", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, nil)
		status, body := f.get(t, "localhost", f.upstreamPort(t))
		if status != http.StatusForbidden || !strings.Contains(body, errPrivateDestination.Error()) {
			t.Fatalf("status=%d body=%s, want 403 private destination", status, body)
		}
		if strings.Contains(body, "127.0.0.1") || strings.Contains(body, "::1") {
			t.Fatalf("the refusal named the internal address: %s", body)
		}
		if f.hits.Load() != 0 {
			t.Fatal("the upstream was reached")
		}
	})

	t.Run("any-host: a private host a service names is allowed", func(t *testing.T) {
		var f *socks5Fixture
		f = newSocks5Fixture(t, resolverFunc(func() (*resolveResult, error) {
			return &resolveResult{SessionID: "s1", Services: []*resolvedService{bearerService("127.0.0.1:" + strconv.Itoa(int(f.upstreamPort(t))))}}, nil
		}), nil)
		if status, body := f.get(t, "127.0.0.1", f.upstreamPort(t)); status != http.StatusOK {
			t.Fatalf("status=%d body=%s", status, body)
		}
	})

	t.Run("any-host: a hidden exception does not make a private host reachable", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, func(ps *proxyServer, _ *Socks5Options, _ *socks5Server) {
			ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost, AllowedHosts: "127.0.0.1"})
		})
		if status, _ := f.get(t, "127.0.0.1", f.upstreamPort(t)); status != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", status)
		}
	})

	t.Run("bundle-hosts: an exception the admin set is allowed", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, func(ps *proxyServer, _ *Socks5Options, _ *socks5Server) {
			ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, AllowedHosts: "127.0.0.1"})
		})
		if status, body := f.get(t, "127.0.0.1", f.upstreamPort(t)); status != http.StatusOK {
			t.Fatalf("status=%d body=%s", status, body)
		}
	})

	t.Run("the opt-out allows it", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, func(ps *proxyServer, _ *Socks5Options, _ *socks5Server) {
			ps.socks5AllowPrivate = true
		})
		if status, body := f.get(t, "127.0.0.1", f.upstreamPort(t)); status != http.StatusOK {
			t.Fatalf("status=%d body=%s", status, body)
		}
	})

	t.Run("the HTTP door is unchanged", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, nil)
		front := httptest.NewServer(http.HandlerFunc(f.ps.dispatch))
		t.Cleanup(front.Close)
		proxyURL, _ := url.Parse(front.URL)
		proxyURL.User = url.UserPassword(ProxyAuthUsername, testSocks5Token)
		client := &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: f.proxyCAs},
		}}
		status, body := do(t, client, http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/x", f.upstreamPort(t)), "")
		if status != http.StatusOK {
			t.Fatalf("status=%d body=%s", status, body)
		}
	})

	t.Run("a missing guarded transport refuses rather than skipping the check", func(t *testing.T) {
		f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, func(ps *proxyServer, _ *Socks5Options, _ *socks5Server) {
			ps.guardedTransport = nil
		})
		if status, _ := f.get(t, "localhost", f.upstreamPort(t)); status != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", status)
		}
	})
}

func TestSocks5ClosesAClientThatSaysNothing(t *testing.T) {
	f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, func(_ *proxyServer, _ *Socks5Options, s *socks5Server) {
		s.stepTimeout = 200 * time.Millisecond
	})
	conn, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the connection was not closed by the server: %v", err)
	}
}

func TestSocks5WaitsOutASlowInfisical(t *testing.T) {
	resolver := &stubResolver{result: &resolveResult{SessionID: "s1"}, delay: 600 * time.Millisecond}
	f := newSocks5Fixture(t, resolver, func(_ *proxyServer, _ *Socks5Options, s *socks5Server) {
		s.stepTimeout = 300 * time.Millisecond
	})
	conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", 443)
	if conn == nil {
		t.Fatalf("a slow Infisical cut the agent off: auth=%#x rep=%#x", auth, rep)
	}
	conn.Close()
}

type panickingResolver struct{}

func (panickingResolver) resolve(string, *sessionLogGrant) (*resolveResult, error) {
	panic("boom")
}

func TestSocks5RecoversAPanickingConnection(t *testing.T) {
	var logs bytes.Buffer
	restore := log.Logger
	log.Logger = zerolog.New(&syncWriter{w: &logs})
	t.Cleanup(func() { log.Logger = restore })

	f := newSocks5Fixture(t, panickingResolver{}, nil)
	_, _, _ = dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, "127.0.0.1", 443)
	f.server.wait()
	if !strings.Contains(logs.String(), "panicked") {
		t.Fatalf("the panic was not logged: %s", logs.String())
	}
	// The listener still accepts.
	conn, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatalf("the listener stopped after a panic: %v", err)
	}
	conn.Close()
}

func TestSocks5WarnsWhenAClientSkipsTLS(t *testing.T) {
	var logs bytes.Buffer
	restore := log.Logger
	log.Logger = zerolog.New(&syncWriter{w: &logs})
	t.Cleanup(func() { log.Logger = restore })

	f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}}, nil)
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", f.addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte{5, 1, 2})
		_, _ = io.ReadAll(conn)
		conn.Close()
	}
	f.server.wait()
	if n := strings.Count(logs.String(), "spoke plain SOCKS5"); n != 1 {
		t.Fatalf("warned %d times, want once: %s", n, logs.String())
	}
}

// A listener whose first Accept fails with a temporary error, then hands out a real connection.
type flakyListener struct {
	net.Listener
	failed atomic.Bool
}

type temporaryErr struct{}

func (temporaryErr) Error() string   { return "too many open files" }
func (temporaryErr) Temporary() bool { return true }
func (temporaryErr) Timeout() bool   { return false }

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.failed.CompareAndSwap(false, true) {
		return nil, temporaryErr{}
	}
	return l.Listener.Accept()
}

func TestSocks5RetriesATemporaryAcceptError(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{transport: newUpstreamTransport(), guardedTransport: newGuardedUpstreamTransport(), ca: newCaManager(key, cert)}
	ps.cache = newSessionCache(&stubResolver{result: &resolveResult{SessionID: "s1"}}, ps.pollInterval)
	server := newSocks5Server(ps, socks5TLSConfig(ps.ca, &Socks5Options{TLSName: "127.0.0.1"}))
	done := make(chan error, 1)
	go func() { done <- server.serve(&flakyListener{Listener: raw}) }()

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	conn, auth, rep := dialSocks5(t, raw.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}, "", testSocks5Token, "127.0.0.1", 443)
	if conn == nil {
		t.Fatalf("no tunnel after a temporary accept error: auth=%#x rep=%#x", auth, rep)
	}
	conn.Close()

	_ = raw.Close()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v after the listener closed, want nil", err)
	}
	server.wait()
}

type resolverFunc func() (*resolveResult, error)

func (f resolverFunc) resolve(string, *sessionLogGrant) (*resolveResult, error) { return f() }

// Handlers log from their own goroutines, so the buffer a test reads must be safe to write concurrently.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func selfSignedListenerCert(t *testing.T, name string, notAfter time.Time) (certPEM, keyPEM string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notAfter.Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(parsed)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), pool
}
