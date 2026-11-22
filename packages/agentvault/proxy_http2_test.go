package agentvault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"golang.org/x/net/http/httpguts"
)

// An HTTP/2 upstream that answers like a gRPC server: it needs "TE: trailers", echoes each chunk of the body as it
// arrives, and puts its status in a trailer.
func newGRPCLikeUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "upstream got "+r.Proto, http.StatusHTTPVersionNotSupported)
			return
		}
		if !httpguts.HeaderValuesContainsToken(r.Header.Values("Te"), "trailers") {
			http.Error(w, "missing TE: trailers", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("X-Seen-Authorization", r.Header.Get("Authorization"))
		w.Header().Set("X-Seen-Remote-Addr", r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		buf := make([]byte, 64)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				break
			}
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+HeaderDecision, "spoofed")
		w.Header().Set(http.TrailerPrefix+HeaderError, "spoofed")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	return upstream
}

func newHTTP2Proxy(t *testing.T, upstream *httptest.Server, http2Hosts string, services []*resolvedService) *http.Client {
	t.Helper()
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	transport := newUpstreamTransport()
	transport.TLSClientConfig = &tls.Config{RootCAs: upstreamPool}

	ps := &proxyServer{transport: transport, ca: newCaManager(key, cert)}
	ps.http2Hosts = parseHostPatterns(http2Hosts)
	ps.http2Base = transport
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(fixedResolver{services: services}, ps.pollInterval)
	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)

	clientPool := x509.NewCertPool()
	clientPool.AddCert(cert)
	proxyURL, _ := url.Parse(front.URL)
	proxyURL.User = url.UserPassword(ProxyAuthUsername, "agv_tok")
	return &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: clientPool},
		ForceAttemptHTTP2: true,
	}}
}

func grpcLikeRequest(t *testing.T, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	return req
}

func TestAnHTTP2HostIsBrokeredOverHTTP2WithTrailers(t *testing.T) {
	upstream := newGRPCLikeUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	svc := policyService(host, nil, nil, nil, nil)
	svc.credential = credential{kind: credentialBearer, headerName: "Authorization", headerPrefix: "Bearer", value: []byte("tok")}
	client := newHTTP2Proxy(t, upstream, host, []*resolvedService{svc})

	resp, err := client.Do(grpcLikeRequest(t, "https://"+host+"/grpc.Echo/Call", strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK || string(body) != "payload" {
		t.Fatalf("got %s %d: %q", resp.Proto, resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer tok" {
		t.Fatalf("upstream saw Authorization %q", got)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer %q, want 0", got)
	}
	for _, name := range []string{HeaderDecision, HeaderError} {
		if got := resp.Trailer.Get(name); got != "" {
			t.Fatalf("the upstream set the proxy's own %s trailer to %q", name, got)
		}
	}
}

// An upstream that fails takes down only the streams of the agent connection that already shares its fate.
func TestEachHTTP2AgentConnectionGetsItsOwnUpstreamConnection(t *testing.T) {
	upstream := newGRPCLikeUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	client := newHTTP2Proxy(t, upstream, host, []*resolvedService{policyService(host, nil, nil, nil, nil)})

	upstreamConn := func() string {
		t.Helper()
		resp, err := client.Do(grpcLikeRequest(t, "https://"+host+"/grpc.Echo/Call", strings.NewReader("payload")))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		if resp.ProtoMajor != 2 {
			t.Fatalf("got %s, want HTTP/2", resp.Proto)
		}
		return resp.Header.Get("X-Seen-Remote-Addr")
	}
	first := upstreamConn()
	if again := upstreamConn(); again != first {
		t.Fatalf("one agent connection used upstream connections %s and %s, want one", first, again)
	}
	client.Transport.(*http.Transport).CloseIdleConnections()
	if next := upstreamConn(); next == first {
		t.Fatalf("a new agent connection reused upstream connection %s", first)
	}
}

func TestAHostNotListedForHTTP2StaysOnHTTP1(t *testing.T) {
	upstream := newGRPCLikeUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	client := newHTTP2Proxy(t, upstream, "other.example.com", []*resolvedService{policyService(host, nil, nil, nil, nil)})

	resp, err := client.Do(grpcLikeRequest(t, "https://"+host+"/grpc.Echo/Call", strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 1 || resp.StatusCode != http.StatusHTTPVersionNotSupported {
		t.Fatalf("got %s %d, want HTTP/1.1 on both legs", resp.Proto, resp.StatusCode)
	}
}

// Each message is sent only after the reply to the one before, so a proxy that waits for the end of the body
// never answers. A refreshable credential and a hook are the two paths that would otherwise read it.
func TestABidiGRPCCallStreamsThroughAHookAndARefreshableCredential(t *testing.T) {
	upstream := newGRPCLikeUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	svc := policyService(host, nil, nil, nil, nil)
	svc.id, svc.accessBundleID = "svc-1", "bundle-1"
	svc.credential = oauthToken("oauth-access-token")
	svc.hook = fake.hook()
	client := newHTTP2Proxy(t, upstream, host, []*resolvedService{svc})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, pw := io.Pipe()
	resp, err := client.Do(grpcLikeRequest(t, "https://"+host+"/grpc.Echo/Chat", pr).WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, msg := range []string{"first", "second"} {
		if _, err := io.WriteString(pw, msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(resp.Body, got); err != nil || string(got) != msg {
			t.Fatalf("reply %q, %v; want %q", got, err, msg)
		}
	}
	_ = pw.Close()
	_, _ = io.ReadAll(resp.Body)

	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer oauth-access-token" {
		t.Fatalf("upstream saw Authorization %q", got)
	}
	if req := fake.only(t).payload(t).Request; req == nil || !req.BodyTruncated || req.Body != "" {
		t.Fatalf("hook was asked with %+v, want the call with no body, marked truncated", req)
	}
}

func TestAnMCPCallLabelledGRPCOnAnHTTP2HostAsksAToolNarrowedHook(t *testing.T) {
	upstream := newGRPCLikeUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	svc := policyService(host, nil, nil, nil, nil)
	svc.kind = serviceKindMCP
	svc.hook = fake.hook(api.AgentVaultServiceHook{Tools: []string{"refund"}})
	client := newHTTP2Proxy(t, upstream, host, []*resolvedService{svc})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"refund"}}`
	resp, err := client.Do(grpcLikeRequest(t, "https://"+host+"/mcp", strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	fake.only(t)
}
