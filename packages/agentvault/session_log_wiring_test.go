package agentvault

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type grantingResolver struct {
	services []*resolvedService
}

func (g grantingResolver) resolve(string, *sessionLogGrant) (*resolveResult, error) {
	return &resolveResult{
		SessionID:  "s1",
		Services:   g.services,
		SessionLog: &sessionLogGrant{sessionID: "s1", key: make([]byte, 32)},
	}, nil
}

func newRecordingProxy(t *testing.T, policy string, services []*resolvedService) (*httptest.Server, *sessionLogRecorder, *fakeShipper) {
	t.Helper()

	shipper := &fakeShipper{}
	ps := &proxyServer{transport: newUpstreamTransport()}
	ps.setConfig(ProxyConfig{TrafficPolicy: policy})
	ps.cache = newSessionCache(grantingResolver{services: services}, ps.pollInterval)
	ps.sessionLogs = newSessionLogRecorder("proxy-1", shipper)

	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)
	return front, ps.sessionLogs, shipper
}

func proxiedGet(t *testing.T, front *httptest.Server, target string) *http.Response {
	t.Helper()

	proxyURL, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("infisical", "agv_test-token")

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	res, err := client.Get(target)
	if err != nil {
		t.Fatalf("request through the proxy failed: %v", err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func drainOneRecord(t *testing.T, log *sessionLogRecorder) sessionLogRecord {
	t.Helper()
	spool, ok := log.spools["s1"]
	if !ok {
		t.Fatal("the request produced no session log spool")
	}
	records := spool.ring.drain(10)
	if len(records) != 1 {
		t.Fatalf("expected exactly one record, got %d", len(records))
	}
	return records[0]
}

func TestAProxiedRequestIsRecorded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, nil)
	res := proxiedGet(t, front, upstream.URL+"/repos/acme/web/issues")
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("upstream status was %d", res.StatusCode)
	}

	got := drainOneRecord(t, log)
	if got.Method != http.MethodGet || got.Path != "/repos/acme/web/issues" || got.Status != http.StatusCreated {
		t.Fatalf("record is %+v", got)
	}
	if got.Decision != decisionPassthrough {
		t.Fatalf("decision was %q, expected %q", got.Decision, decisionPassthrough)
	}
	if got.Service != nil || got.AccessBundle != nil {
		t.Fatal("a passthrough record named a service")
	}
	if got.ProxyID != "proxy-1" {
		t.Fatalf("record names proxy %q", got.ProxyID)
	}
}

func TestAQueryStringNeverReachesTheRecord(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, nil)
	proxiedGet(t, front, upstream.URL+"/v1/thing?access_token=super-secret&sid=abc")

	got := drainOneRecord(t, log)
	if got.Path != "/v1/thing" {
		t.Fatalf("path is %q, a query string leaked into the record", got.Path)
	}
}

func TestASubstitutedPathIsRecordedAsTheAgentSentIt(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "http://")
	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, []*resolvedService{
		policyService(host, nil, nil, nil, []substitution{subOn("__PAT__", "real-token", surfacePath)}),
	})
	proxiedGet(t, front, upstream.URL+"/repos/__PAT__/issues")

	if upstreamPath := <-seen; upstreamPath != "/repos/real-token/issues" {
		t.Fatalf("the upstream saw %q, so the substitution never fired and this proves nothing", upstreamPath)
	}
	got := drainOneRecord(t, log)
	if got.Path != "/repos/__PAT__/issues" || strings.Contains(got.Path, "real-token") {
		t.Fatalf("record path is %q", got.Path)
	}
	if got.Decision != decisionBrokered {
		t.Fatalf("decision was %q, expected a substitution to count as brokered", got.Decision)
	}
}

func TestABlockedRequestIsRecordedWithItsRefusal(t *testing.T) {
	front, log, _ := newRecordingProxy(t, TrafficPolicyBundleHosts, nil)

	res := proxiedGet(t, front, "http://blocked.example/collect")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a blocked host answered %d", res.StatusCode)
	}

	got := drainOneRecord(t, log)
	if got.Decision != decisionBlocked || got.Status != http.StatusForbidden {
		t.Fatalf("record is %+v, expected a blocked 403", got)
	}
	if got.Host != "blocked.example" {
		t.Fatalf("record names host %q", got.Host)
	}
}

func TestAnOversizedMethodIsRecordedTruncated(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer upstream.Close()

	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, nil)

	proxyURL, _ := url.Parse(front.URL)
	proxyURL.User = url.UserPassword("infisical", "agv_test-token")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, err := http.NewRequest(strings.Repeat("A", 5000), upstream.URL+"/v1/thing", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("the proxy did not answer: %v", err)
	}
	defer res.Body.Close()

	got := drainOneRecord(t, log)
	if len(got.Method) > maxLoggedMethodLen+len("...[truncated]") {
		t.Fatalf("the record kept a %d-byte method; an agent could inflate its own records", len(got.Method))
	}
}

func TestRecordingSurvivesAnUnreachableUpstream(t *testing.T) {
	front, log, _ := newRecordingProxy(t, TrafficPolicyAnyHost, nil)

	proxyURL, _ := url.Parse(front.URL)
	proxyURL.User = url.UserPassword("infisical", "agv_test-token")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	res, err := client.Get("http://127.0.0.1:1/v1/thing")
	if err != nil {
		t.Fatalf("the proxy did not answer: %v", err)
	}
	defer res.Body.Close()

	got := drainOneRecord(t, log)
	if got.Decision != decisionError {
		t.Fatalf("decision was %q, expected %q", got.Decision, decisionError)
	}
}

func TestAWholeRequestRoundTripsFromProxyToSealedChunk(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	front, log, shipper := newRecordingProxy(t, TrafficPolicyAnyHost, nil)
	for i := 0; i < 3; i++ {
		proxiedGet(t, front, fmt.Sprintf("%s/v1/thing/%d", upstream.URL, i))
	}

	log.close(context.Background())

	posts := shipper.posts()
	if len(posts) != 1 {
		t.Fatalf("three requests produced %d chunks, expected one", len(posts))
	}
	if posts[0].sessionID != "s1" {
		t.Fatalf("the chunk was filed under session %q", posts[0].sessionID)
	}
	if posts[0].bytes <= 0 {
		t.Fatal("the chunk declared no ciphertext")
	}

	puts := shipper.puts()
	if len(puts) != 1 || puts[0].bytes != posts[0].bytes {
		t.Fatalf("uploaded %d objects, %d bytes, for a chunk declaring %d", len(puts), puts[0].bytes, posts[0].bytes)
	}

	if bytes.Contains(puts[0].body, []byte("/v1/thing")) || bytes.Contains(puts[0].body, []byte("\"method\"")) {
		t.Fatal("the uploaded chunk contains readable record fields; it was not sealed")
	}
}
