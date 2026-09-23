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

// grantingResolver hands back one service plus an activity grant, so a request driven through the real
// dispatch path produces a real record.
type grantingResolver struct {
	services []*resolvedService
}

func (g grantingResolver) resolve(string, *activityGrant) (*resolveResult, error) {
	return &resolveResult{
		SessionID: "s1",
		Services:  g.services,
		Activity:  &activityGrant{sessionID: "s1", projectID: "proj-1", key: make([]byte, 32)},
	}, nil
}

// newRecordingProxy wires a proxy exactly as run.go does, minus the listener, so these tests exercise
// the call site in forwardHTTP rather than activityLog in isolation.
func newRecordingProxy(t *testing.T, policy string, services []*resolvedService) (*httptest.Server, *activityLog, *fakeShipper) {
	t.Helper()

	shipper := &fakeShipper{}
	ps := &proxyServer{transport: newUpstreamTransport()}
	ps.setConfig(ProxyConfig{TrafficPolicy: policy})
	ps.cache = newSessionCache(grantingResolver{services: services}, ps.pollInterval)
	ps.activity = newActivityLog("proxy-1", shipper)

	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)
	return front, ps.activity, shipper
}

func proxiedGet(t *testing.T, front *httptest.Server, target string) *http.Response {
	t.Helper()

	proxyURL, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	// The session token rides in the proxy credentials, which is how an agent presents it.
	proxyURL.User = url.UserPassword("infisical", "agv_test-token")

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	res, err := client.Get(target)
	if err != nil {
		t.Fatalf("request through the proxy failed: %v", err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func drainOneRecord(t *testing.T, log *activityLog) activityRecord {
	t.Helper()
	spool, ok := log.spools["s1"]
	if !ok {
		t.Fatal("the request produced no activity spool")
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
	// Nothing in the bundle matched, so this is passthrough traffic. Recording it is the whole point:
	// under the default any-host policy an agent exfiltrating to an unconfigured host looks like this.
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
	// Plenty of APIs put a token in the query string, so the path is built from EscapedPath() and the
	// query is never seen. This is true by construction; the test is what keeps it true.
	proxiedGet(t, front, upstream.URL+"/v1/thing?access_token=super-secret&sid=abc")

	got := drainOneRecord(t, log)
	if got.Path != "/v1/thing" {
		t.Fatalf("path is %q, a query string leaked into the record", got.Path)
	}
}

// A path substitution rewrites the request with the real credential before it goes upstream. The record
// has to carry the path the agent sent, placeholder and all, or the activity log would be the one place
// the secret the agent never sees gets written down.
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
	// bundle-hosts with no service covering the host, and no allow list: the request is refused.
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
	// A valid token, so Go sends it. Only the header limit stops an agent sending one far longer.
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
	// Port 1 refuses immediately.
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

	// close is what shutdown calls: it flushes whatever is buffered within the deadline.
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

	// What leaves the proxy is ciphertext. If the records ever went out in the clear, the host and the
	// path would be readable right here.
	if bytes.Contains(puts[0].body, []byte("/v1/thing")) || bytes.Contains(puts[0].body, []byte("\"method\"")) {
		t.Fatal("the uploaded chunk contains readable record fields; it was not sealed")
	}
}
