package agentvault

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
)

// What one request the proxy forwarded to Infisical carried.
type forwardedRequest struct {
	method, path, rawQuery, authorization, proxyID, proxyVersion string
}

// A stand-in for the proxy's Infisical, installed as config.INFISICAL_URL for the test.
type fakeInfisical struct {
	mu       sync.Mutex
	requests []forwardedRequest
	status   int
	body     string
	// Runs before each answer, so a test can hold requests open.
	before func()
}

func newFakeInfisical(t *testing.T, status int, body string) *fakeInfisical {
	t.Helper()
	f := &fakeInfisical{status: status, body: body}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, forwardedRequest{
			method:        r.Method,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"),
			proxyID:       r.Header.Get(headerProxyID),
			proxyVersion:  r.Header.Get(headerProxyVersion),
		})
		before := f.before
		f.mu.Unlock()
		if before != nil {
			before()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.body)
	}))
	t.Cleanup(server.Close)
	old := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })
	return f
}

func (f *fakeInfisical) seen() []forwardedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]forwardedRequest(nil), f.requests...)
}

type goneResolver struct{}

func (goneResolver) resolve(string, *sessionLogGrant) (*resolveResult, error) {
	return nil, errSessionGone
}

// The same client, with another session token in its proxy URL.
func withSessionToken(t *testing.T, client *http.Client, token string) *http.Client {
	t.Helper()
	transport := client.Transport.(*http.Transport).Clone()
	proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: DiscoveryHost}})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword(ProxyAuthUsername, token)
	transport.Proxy = http.ProxyURL(proxyURL)
	return &http.Client{Transport: transport}
}

func noUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the reserved name must never reach an upstream")
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

func getThrough(t *testing.T, client *http.Client, target string, header http.Header) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	for name, values := range header {
		req.Header[name] = values
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestTheServicesListComesFromTheProxysInfisicalWithTheSessionsOwnToken(t *testing.T) {
	const list = `{"agentVault":{"proxy":"prod-proxy"},"services":[]}`
	infisical := newFakeInfisical(t, http.StatusOK, list)
	ps, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	ps.opts.ProxyID = "proxy-1"

	// An agent handed someone else's token can't use it here: the proxy sends the session's own.
	resp, body := getThrough(t, client, DiscoveryURL, http.Header{"Authorization": {"Bearer agv_someone_else"}})
	if resp.StatusCode != http.StatusOK || body != list || resp.Header.Get(HeaderDecision) != decisionDiscovery ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("got %d (%s): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), body)
	}
	// Infisical's length is passed on, so an answer that stops short can't pass for a whole one.
	if resp.ContentLength != int64(len(list)) {
		t.Fatalf("Content-Length %d, want %d", resp.ContentLength, len(list))
	}
	seen := infisical.seen()
	want := forwardedRequest{method: http.MethodGet, path: "/api/v1/agent-vault/session/services",
		authorization: "Bearer agv_tok", proxyID: "proxy-1", proxyVersion: util.CLI_VERSION}
	if len(seen) != 1 || seen[0] != want {
		t.Fatalf("Infisical saw %+v, want %+v", seen, want)
	}
}

func TestTheShortAddressAndTheAPIPathReachTheSameList(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{"services":[]}`)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	for _, path := range []string{"/", "/services", "/api/v1/agent-vault/session/services"} {
		if resp, _ := getThrough(t, client, "https://"+DiscoveryHost+path, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s answered %d", path, resp.StatusCode)
		}
	}
	for _, request := range infisical.seen() {
		if request.path != "/api/v1/agent-vault/session/services" {
			t.Fatalf("forwarded to %q", request.path)
		}
	}
}

func TestSkillsAreForwardedWithTheirQuery(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{"skills":[]}`)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	resp, _ := getThrough(t, client, "https://"+DiscoveryHost+"/api/v1/agent-vault/session/skills?includeBuiltin=false", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderDecision) != decisionInfisical {
		t.Fatalf("got %d (%s)", resp.StatusCode, resp.Header.Get(HeaderDecision))
	}
	seen := infisical.seen()
	if len(seen) != 1 || seen[0].path != "/api/v1/agent-vault/session/skills" || seen[0].rawQuery != "includeBuiltin=false" {
		t.Fatalf("Infisical saw %+v", seen)
	}
}

func TestNothingElseInInfisicalIsReachableThroughTheReservedName(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{}`)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})

	resp, body := getThrough(t, client, "https://"+DiscoveryHost+"/api/v1/agent-vault/session/revoke", nil)
	if refusal := decodeProxyError(t, body); resp.StatusCode != http.StatusNotFound || refusal.Error != errorCodeNotFound ||
		resp.Header.Get(HeaderDecision) != decisionBlocked {
		t.Fatalf("an unlisted path got %d (%s): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), body)
	}

	post, _ := http.NewRequest(http.MethodPost, DiscoveryURL, nil)
	postResp, err := client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST got %d, want 405", postResp.StatusCode)
	}
	if seen := infisical.seen(); len(seen) != 0 {
		t.Fatalf("Infisical was asked for %+v", seen)
	}
}

// A refused tunnel tells curl only "CONNECT tunnel failed, response 403". The reserved name opens anyway for a
// well-formed token, so the refusal arrives as JSON with its hint, inside TLS.
func TestARefusedSessionExplainsItselfInsideTheTunnel(t *testing.T) {
	newFakeInfisical(t, http.StatusOK, `{}`)
	_, base := newTLSProxy(t, noUpstream(t), goneResolver{})
	client := withSessionToken(t, base, testSocks5Token)

	resp, body := getThrough(t, client, DiscoveryURL, nil)
	refusal := decodeProxyError(t, body)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(HeaderDecision) != decisionBlocked ||
		refusal.Error != errorCodeSessionInvalid || refusal.Hint == "" {
		t.Fatalf("got %d (%s): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), body)
	}

	// Any other host is still refused at the tunnel, before the proxy does any work for the caller.
	if _, err := client.Get("https://api.github.com/"); err == nil {
		t.Fatal("a gone session opened a tunnel to an ordinary host")
	}
}

func TestInfisicalsOwnRefusalIsPassedOnUnchanged(t *testing.T) {
	const refusal = `{"statusCode":401,"error":"UnauthorizedError","message":"This session has been revoked"}`
	newFakeInfisical(t, http.StatusUnauthorized, refusal)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	resp, body := getThrough(t, client, DiscoveryURL, nil)
	if resp.StatusCode != http.StatusUnauthorized || body != refusal || resp.Header.Get(HeaderDecision) != decisionDiscovery {
		t.Fatalf("got %d (%s): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), body)
	}
}

func TestAnUnreachableInfisicalIsTheProxysOwnAnswer(t *testing.T) {
	gone := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	gone.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = gone.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })

	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	resp, body := getThrough(t, client, DiscoveryURL, nil)
	refusal := decodeProxyError(t, body)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(HeaderDecision) != decisionError ||
		refusal.Error != errorCodeInfisicalUnreachable || refusal.Hint == "" || !IsInfisicalForwardRefusal(refusal.Error) {
		t.Fatalf("got %d (%s): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), body)
	}
}

func TestTheReservedNameOverPlainHTTPAndTheSocks5Door(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{"services":[]}`)

	front, _, _ := newRecordingProxy(t, TrafficPolicyBundleHosts, nil)
	if res := proxiedGet(t, front, "http://"+DiscoveryHost+"/services"); res.StatusCode != http.StatusOK {
		t.Fatalf("plain http got %d", res.StatusCode)
	}

	// E2B hands the SOCKS5 door a hostname (ATYP domain) when an allowOut domain entry matches, on port 80 or 443. The
	// sandbox still has to resolve the name first, so E2B needs it pinned in the sandbox's /etc/hosts.
	f := newSocks5Fixture(t, fixedResolver{}, nil)
	for _, port := range []uint16{443, 80} {
		conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, DiscoveryHost, port)
		if conn == nil {
			t.Fatalf("port %d: tunnel refused: auth=%#x rep=%#x", port, auth, rep)
		}
		var rw io.ReadWriter = conn
		scheme := "http"
		if port == 443 {
			rw = tls.Client(conn, &tls.Config{RootCAs: f.proxyCAs, ServerName: DiscoveryHost})
			scheme = "https"
		}
		req, _ := http.NewRequest(http.MethodGet, scheme+"://"+DiscoveryHost+"/services", nil)
		if err := req.Write(rw); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(rw), req)
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderDecision) != decisionDiscovery {
			t.Fatalf("port %d: got %d (%s)", port, resp.StatusCode, resp.Header.Get(HeaderDecision))
		}
		_ = conn.Close()
	}
	if got := len(infisical.seen()); got != 3 {
		t.Fatalf("Infisical got %d requests, want 3", got)
	}
}

func TestReservedNameRequestsAreRecordedInTheSessionLog(t *testing.T) {
	newFakeInfisical(t, http.StatusOK, `{"services":[]}`)
	front, log, _ := newRecordingProxy(t, TrafficPolicyBundleHosts, nil)

	for _, tc := range []struct{ path, decision string }{
		{"/services", decisionDiscovery},
		{"/api/v1/agent-vault/session/skills", decisionInfisical},
	} {
		if res := proxiedGet(t, front, "http://"+DiscoveryHost+tc.path); res.StatusCode != http.StatusOK {
			t.Fatalf("%s answered %d", tc.path, res.StatusCode)
		}
		got := drainOneRecord(t, log)
		if got.Decision != tc.decision || got.Host != DiscoveryHost || got.Path != tc.path || got.Status != http.StatusOK ||
			got.Service != nil || got.ServiceType != nil {
			t.Fatalf("record is %+v", got)
		}
	}

	if res := proxiedGet(t, front, "http://"+DiscoveryHost+"/admin"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", res.StatusCode)
	}
	if got := drainOneRecord(t, log); got.Decision != decisionBlocked || got.Status != http.StatusNotFound || got.Path != "/admin" {
		t.Fatalf("record is %+v", got)
	}
}

func TestTheProxysOwnSessionEndpointsAreGone(t *testing.T) {
	front, _, _ := newRecordingProxy(t, TrafficPolicyAnyHost, nil)
	for _, path := range []string{"/_agent-vault/services", "/_agent-vault/skills"} {
		resp, err := http.Get(front.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s answered %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestTheProxyQueuesRequestsToInfisicalPastItsLimit(t *testing.T) {
	limit := cap(reservedForwardSlots)
	release := make(chan struct{})
	var inFlight, most atomic.Int64
	infisical := newFakeInfisical(t, http.StatusOK, `{"skills":[]}`)
	infisical.before = func() {
		n := inFlight.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
	}
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})

	statuses := make(chan int, limit+2)
	for i := 0; i < limit+2; i++ {
		go func() {
			resp, err := client.Get("http://" + DiscoveryHost + "/api/v1/agent-vault/session/skills")
			if err != nil {
				statuses <- 0
				return
			}
			resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	for deadline := time.Now().Add(5 * time.Second); inFlight.Load() < int64(limit) && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	// Room for a request past the limit to reach Infisical, if the limit let it.
	time.Sleep(100 * time.Millisecond)
	close(release)

	for i := 0; i < limit+2; i++ {
		if status := <-statuses; status != http.StatusOK {
			t.Fatalf("a request got %d, want every one to wait its turn and get 200", status)
		}
	}
	if most.Load() != int64(limit) {
		t.Fatalf("Infisical had %d requests at once, want %d", most.Load(), limit)
	}
}

func TestResponsesCarryTheProxysDecisionNotTheUpstreams(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderDecision, "brokered")
		w.Header().Set(HeaderService, "forged")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	host := "127.0.0.1:" + upstreamURL.Port()

	brokered := policyService(host, nil, nil, nil, nil)
	brokered.credential = credential{kind: credentialBearer, headerName: "Authorization", headerPrefix: "Bearer ", value: []byte("real")}
	_, client := newTLSProxy(t, upstream, fixedResolver{services: []*resolvedService{brokered}})

	resp, err := client.Get("https://" + host + "/repos")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get(HeaderDecision) != decisionBrokered || resp.Header.Get(HeaderService) != "github" {
		t.Fatalf("a brokered 401 should say so: decision=%q service=%q", resp.Header.Get(HeaderDecision), resp.Header.Get(HeaderService))
	}

	_, passClient := newTLSProxy(t, upstream, fixedResolver{})
	resp, err = passClient.Get("https://" + host + "/repos")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get(HeaderDecision) != decisionPassthrough || resp.Header.Get(HeaderService) != "" {
		t.Fatalf("the upstream's own headers must not survive: decision=%q service=%q", resp.Header.Get(HeaderDecision), resp.Header.Get(HeaderService))
	}
}

// An Infisical that declares a length and sends less, the way a connection that drops part way looks.
func newShortInfisical(t *testing.T, declared int, sent string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(declared))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, sent)
	}))
	t.Cleanup(server.Close)
	old := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })
}

// readsWhole reports whether the agent got a status and then read the body to its end without an error.
func readsWhole(client *http.Client, target string) bool {
	resp, err := client.Get(target)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	return err == nil
}

func TestAnAnswerThatStopsPartWayDoesNotReachTheAgentAsWhole(t *testing.T) {
	newShortInfisical(t, 1000, `{"services":`)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	if readsWhole(client, DiscoveryURL) {
		t.Fatal("the agent read a cut answer as a whole one")
	}
}

func TestAnAnswerPastTheLimitIsCutOffVisibly(t *testing.T) {
	old := reservedForwardMaxBytes
	reservedForwardMaxBytes = 16
	t.Cleanup(func() { reservedForwardMaxBytes = old })
	newFakeInfisical(t, http.StatusOK, strings.Repeat("x", 100))
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	if readsWhole(client, DiscoveryURL) {
		t.Fatal("the agent read an answer over the limit as a whole one")
	}
}

func TestAnAgentThatStopsReadingGivesUpItsSlot(t *testing.T) {
	old := reservedForwardTimeout
	reservedForwardTimeout = 300 * time.Millisecond
	t.Cleanup(func() { reservedForwardTimeout = old })
	// Far more than the buffers between the proxy and the agent hold, so the proxy's writes stall.
	newFakeInfisical(t, http.StatusOK, strings.Repeat("x", 32<<20))
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})

	resp, err := client.Get(DiscoveryURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The write that times out closes the connection, and Go's TLS gives the closing alert 5 seconds of its own when the
	// agent's buffers are full. Far short of the tunnel's half-hour write timeout either way.
	for deadline := time.Now().Add(10 * time.Second); len(reservedForwardSlots) > 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the proxy still holds %d slots for an agent that stopped reading", len(reservedForwardSlots))
		}
	}
}
