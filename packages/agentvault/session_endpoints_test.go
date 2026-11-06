package agentvault

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
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
	"github.com/go-resty/resty/v2"
)

// The proxy's own Infisical in these tests. Agents reach it through the proxy, and the proxy reaches the stand-in for it
// that useInfisicalServer installs, so the name never has to resolve.
const testInfisicalHost = "infisical.test"

// What one request the proxy forwarded to Infisical carried.
type forwardedRequest struct {
	method, path, rawQuery, authorization, proxyID, proxyVersion string
}

// A stand-in for the proxy's Infisical.
type fakeInfisical struct {
	mu       sync.Mutex
	requests []forwardedRequest
	status   int
	body     string
	// Runs before each answer, so a test can hold requests open.
	before func()
	// The API URL the proxy was started with.
	apiURL string
}

func newFakeInfisical(t *testing.T, status int, body string) *fakeInfisical {
	t.Helper()
	return newFakeInfisicalAt(t, "https", status, body)
}

// newFakeInfisicalAt installs a stand-in for an Infisical whose API URL has scheme.
func newFakeInfisicalAt(t *testing.T, scheme string, status int, body string) *fakeInfisical {
	t.Helper()
	f := &fakeInfisical{status: status, body: body}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})
	var server *httptest.Server
	if scheme == "https" {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	f.apiURL = useInfisicalServer(t, scheme, server)
	return f
}

func (f *fakeInfisical) servicesURL() string { return f.apiURL + sessionServicesPath }
func (f *fakeInfisical) skillsURL() string   { return f.apiURL + sessionSkillsPath }

func (f *fakeInfisical) seen() []forwardedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]forwardedRequest(nil), f.requests...)
}

// useInfisicalServer makes server the proxy's Infisical: --domain names testInfisicalHost with scheme, and the proxy's
// client for the session's endpoints, built as in production, dials server for that name and trusts its certificate.
// It returns the API URL.
func useInfisicalServer(t *testing.T, scheme string, server *httptest.Server) string {
	t.Helper()
	apiURL := scheme + "://" + testInfisicalHost + "/api"
	oldURL := config.INFISICAL_URL
	config.INFISICAL_URL = apiURL
	t.Cleanup(func() { config.INFISICAL_URL = oldURL })

	client, err := newSessionEndpointClient()
	if err != nil {
		t.Fatal(err)
	}
	addr := server.Listener.Addr().String()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if host, _, _ := net.SplitHostPort(target); host == testInfisicalHost {
				target = addr
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
	if server.TLS != nil {
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		// httptest's certificate names example.com rather than the test host.
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "example.com"}
	}
	client.SetTransport(transport)
	oldClient := sessionEndpointClient
	sessionEndpointClient = func() (*resty.Client, error) { return client, nil }
	t.Cleanup(func() { sessionEndpointClient = oldClient })
	return apiURL
}

type goneResolver struct{}

func (goneResolver) resolve(string, *sessionLogGrant) (*resolveResult, error) {
	return nil, errSessionGone
}

// The same client, with another session token in its proxy URL.
func withSessionToken(t *testing.T, client *http.Client, token string) *http.Client {
	t.Helper()
	transport := client.Transport.(*http.Transport).Clone()
	proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: testInfisicalHost}})
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
		t.Error("the session's endpoints must never reach an upstream")
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
	resp, body := getThrough(t, client, infisical.servicesURL(), http.Header{"Authorization": {"Bearer agv_someone_else"}})
	if resp.StatusCode != http.StatusOK || body != list || resp.Header.Get(HeaderDecision) != decisionDiscovery ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("got %d (%s): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), body)
	}
	// Inside TLS the proxy names its Infisical again, which is what lets agent-vault run trust the CONNECT answer's claim.
	if got := resp.Header.Get(HeaderAPIURL); got != infisical.apiURL {
		t.Fatalf("the answer named %q, want %q", got, infisical.apiURL)
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

func TestSkillsAreForwardedWithTheirQuery(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{"skills":[]}`)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	resp, _ := getThrough(t, client, infisical.skillsURL()+"?includeBuiltin=false", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderDecision) != decisionSkills {
		t.Fatalf("got %d (%s)", resp.StatusCode, resp.Header.Get(HeaderDecision))
	}
	seen := infisical.seen()
	if len(seen) != 1 || seen[0].path != "/api/v1/agent-vault/session/skills" || seen[0].rawQuery != "includeBuiltin=false" {
		t.Fatalf("Infisical saw %+v", seen)
	}
}

func TestOnlyTheSessionsEndpointsOnTheProxysInfisicalGetTheSessionsToken(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{}`)
	var upstreamAuth atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)
	_, client := newTLSProxy(t, upstream, fixedResolver{})

	// The same path on another host goes there like any request, with nothing added.
	resp, _ := getThrough(t, client, upstream.URL+"/api"+sessionServicesPath, nil)
	if resp.Header.Get(HeaderDecision) != decisionPassthrough || upstreamAuth.Load() != "" {
		t.Fatalf("another host got %s with Authorization %q", resp.Header.Get(HeaderDecision), upstreamAuth.Load())
	}

	// Another path on the proxy's own Infisical goes like any request too, rather than with the session's token.
	resp, _ = getThrough(t, client, infisical.apiURL+"/v1/agent-vault/session/revoke", nil)
	if decision := resp.Header.Get(HeaderDecision); decision == decisionDiscovery || decision == decisionSkills {
		t.Fatalf("an unlisted path was answered for the session (%s)", decision)
	}

	post, _ := http.NewRequest(http.MethodPost, infisical.servicesURL(), nil)
	postResp, err := client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed || postResp.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST got %d, want 405", postResp.StatusCode)
	}
	if seen := infisical.seen(); len(seen) != 0 {
		t.Fatalf("Infisical was asked for %+v with the session's token", seen)
	}
}

func TestEveryConnectAnswerNamesTheProxysInfisical(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{}`)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	proxyURL, err := client.Transport.(*http.Transport).Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: testInfisicalHost}})
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := proxyURL.Host

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, target := range []string{testInfisicalHost + ":443", "api.github.com:443"} {
		got, err := AskProxyAPIURL(ctx, proxyAddr, "agv_tok", target)
		if err != nil || got != infisical.apiURL {
			t.Fatalf("CONNECT %s named %q (%v), want %q", target, got, err, infisical.apiURL)
		}
	}
}

// A refused tunnel tells curl only "CONNECT tunnel failed, response 403". The proxy's own Infisical opens anyway for a
// well-formed token, so the refusal arrives as JSON with its hint, inside TLS.
func TestARefusedSessionExplainsItselfInsideTheTunnel(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{}`)
	_, base := newTLSProxy(t, noUpstream(t), goneResolver{})
	client := withSessionToken(t, base, testSocks5Token)

	resp, body := getThrough(t, client, infisical.servicesURL(), nil)
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

func TestHintsNameTheServicesListOnTheProxysInfisical(t *testing.T) {
	infisical := newFakeInfisical(t, http.StatusOK, `{}`)
	if hint := proxyErrorHint(errorCodeHostNotAllowed); !strings.Contains(hint, infisical.servicesURL()) {
		t.Fatalf("hint %q doesn't name %s", hint, infisical.servicesURL())
	}
}

func TestInfisicalsOwnRefusalIsPassedOnUnchanged(t *testing.T) {
	const refusal = `{"statusCode":401,"error":"UnauthorizedError","message":"This session has been revoked"}`
	infisical := newFakeInfisical(t, http.StatusUnauthorized, refusal)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	resp, body := getThrough(t, client, infisical.servicesURL(), nil)
	if resp.StatusCode != http.StatusUnauthorized || body != refusal || resp.Header.Get(HeaderDecision) != decisionDiscovery {
		t.Fatalf("got %d (%s): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), body)
	}
}

func TestAnUnreachableInfisicalIsTheProxysOwnAnswer(t *testing.T) {
	gone := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	apiURL := useInfisicalServer(t, "https", gone)
	gone.Close()

	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	resp, body := getThrough(t, client, apiURL+sessionServicesPath, nil)
	refusal := decodeProxyError(t, body)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(HeaderDecision) != decisionError ||
		refusal.Error != errorCodeInfisicalUnreachable || refusal.Hint == "" || !IsInfisicalForwardRefusal(refusal.Error) {
		t.Fatalf("got %d (%s): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), body)
	}
}

func TestTheSessionsEndpointsOverPlainHTTPAndTheSocks5Door(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			infisical := newFakeInfisicalAt(t, scheme, http.StatusOK, `{"services":[]}`)

			if scheme == "http" {
				front, _, _ := newRecordingProxy(t, TrafficPolicyBundleHosts, nil)
				if res := proxiedGet(t, front, infisical.servicesURL()); res.StatusCode != http.StatusOK {
					t.Fatalf("plain http got %d", res.StatusCode)
				}
			}

			// E2B hands the SOCKS5 door a hostname (ATYP domain) when an allowOut domain entry matches, on port 80 or 443.
			port := map[string]uint16{"http": 80, "https": 443}[scheme]
			f := newSocks5Fixture(t, fixedResolver{}, nil)
			conn, auth, rep := dialSocks5(t, f.addr, f.outerTLS(), ProxyAuthUsername, testSocks5Token, testInfisicalHost, port)
			if conn == nil {
				t.Fatalf("tunnel refused: auth=%#x rep=%#x", auth, rep)
			}
			defer conn.Close()
			var rw io.ReadWriter = conn
			if scheme == "https" {
				rw = tls.Client(conn, &tls.Config{RootCAs: f.proxyCAs, ServerName: testInfisicalHost})
			}
			req, _ := http.NewRequest(http.MethodGet, infisical.servicesURL(), nil)
			if err := req.Write(rw); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(rw), req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderDecision) != decisionDiscovery {
				t.Fatalf("got %d (%s)", resp.StatusCode, resp.Header.Get(HeaderDecision))
			}
			want := map[string]int{"http": 2, "https": 1}[scheme]
			if got := len(infisical.seen()); got != want {
				t.Fatalf("Infisical got %d requests, want %d", got, want)
			}
		})
	}
}

func TestSessionEndpointRequestsAreRecordedInTheSessionLog(t *testing.T) {
	infisical := newFakeInfisicalAt(t, "http", http.StatusOK, `{"services":[]}`)
	front, log, _ := newRecordingProxy(t, TrafficPolicyBundleHosts, nil)

	for _, tc := range []struct{ target, path, decision string }{
		{infisical.servicesURL(), "/api/v1/agent-vault/session/services", decisionDiscovery},
		{infisical.skillsURL(), "/api/v1/agent-vault/session/skills", decisionSkills},
	} {
		if res := proxiedGet(t, front, tc.target); res.StatusCode != http.StatusOK {
			t.Fatalf("%s answered %d", tc.path, res.StatusCode)
		}
		got := drainOneRecord(t, log)
		if got.Decision != tc.decision || got.Host != testInfisicalHost || got.Path != tc.path || got.Status != http.StatusOK ||
			got.Service != nil || got.ServiceType != nil {
			t.Fatalf("record is %+v", got)
		}
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
	limit := cap(sessionForwardSlots)
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
			resp, err := client.Get(infisical.skillsURL())
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

// An Infisical that declares a length and sends less, the way a connection that drops part way looks. It returns the
// URL of the services list.
func newShortInfisical(t *testing.T, declared int, sent string) string {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(declared))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, sent)
	}))
	t.Cleanup(server.Close)
	return useInfisicalServer(t, "https", server) + sessionServicesPath
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
	servicesURL := newShortInfisical(t, 1000, `{"services":`)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	if readsWhole(client, servicesURL) {
		t.Fatal("the agent read a cut answer as a whole one")
	}
}

func TestAnAnswerPastTheLimitIsCutOffVisibly(t *testing.T) {
	old := sessionForwardMaxBytes
	sessionForwardMaxBytes = 16
	t.Cleanup(func() { sessionForwardMaxBytes = old })
	infisical := newFakeInfisical(t, http.StatusOK, strings.Repeat("x", 100))
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})
	if readsWhole(client, infisical.servicesURL()) {
		t.Fatal("the agent read an answer over the limit as a whole one")
	}
}

func TestAnAgentThatStopsReadingGivesUpItsSlot(t *testing.T) {
	old := sessionForwardTimeout
	sessionForwardTimeout = 300 * time.Millisecond
	t.Cleanup(func() { sessionForwardTimeout = old })
	// Far more than the buffers between the proxy and the agent hold, so the proxy's writes stall.
	infisical := newFakeInfisical(t, http.StatusOK, strings.Repeat("x", 32<<20))
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})

	resp, err := client.Get(infisical.servicesURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The write that times out closes the connection, and Go's TLS gives the closing alert 5 seconds of its own when the
	// agent's buffers are full. Far short of the tunnel's half-hour write timeout either way.
	for deadline := time.Now().Add(10 * time.Second); len(sessionForwardSlots) > 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the proxy still holds %d slots for an agent that stopped reading", len(sessionForwardSlots))
		}
	}
}

func TestACookieOnOneSessionsAnswerIsNotSentForAnother(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sent = append(sent, r.Header.Get("Cookie"))
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "affinity", Value: "first-session", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"services":[]}`)
	}))
	t.Cleanup(server.Close)
	servicesURL := useInfisicalServer(t, "https", server) + sessionServicesPath
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})

	getThrough(t, client, servicesURL, nil)
	getThrough(t, withSessionToken(t, client, "agv_other"), servicesURL, nil)
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 2 || sent[1] != "" {
		t.Fatalf("Infisical got cookies %q", sent)
	}
}

func TestTheProxyFollowsNoRedirectFromInfisical(t *testing.T) {
	var reached atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		_, _ = io.WriteString(w, "not Infisical")
	}))
	t.Cleanup(elsewhere.Close)
	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/private", http.StatusFound)
	}))
	t.Cleanup(redirecting.Close)
	servicesURL := useInfisicalServer(t, "https", redirecting) + sessionServicesPath
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})

	resp, body := getThrough(t, client, servicesURL, nil)
	if reached.Load() || resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "not Infisical") {
		t.Fatalf("got %d %q; followed the redirect: %v", resp.StatusCode, body, reached.Load())
	}
}

// agent-vault run asks over TLS whatever --domain's scheme, so it can check the answer against the proxy's certificate
// authority.
func TestTheSessionEndpointsAnswerOverTLSWhenTheDomainIsHTTP(t *testing.T) {
	infisical := newFakeInfisicalAt(t, "http", http.StatusOK, `{"skills":[]}`)
	_, client := newTLSProxy(t, noUpstream(t), fixedResolver{})

	resp, body := getThrough(t, client, "https://"+testInfisicalHost+":80/api"+sessionSkillsPath+"?includeBuiltin=false", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderDecision) != decisionSkills ||
		resp.Header.Get(HeaderAPIURL) != infisical.apiURL {
		t.Fatalf("got %d (%s, %q): %s", resp.StatusCode, resp.Header.Get(HeaderDecision), resp.Header.Get(HeaderAPIURL), body)
	}
	if seen := infisical.seen(); len(seen) != 1 || seen[0].authorization != "Bearer agv_tok" || seen[0].rawQuery != "includeBuiltin=false" {
		t.Fatalf("Infisical saw %+v", seen)
	}
}

// --domain may carry credentials for whatever sits in front of Infisical; agents see the URL in headers and hints.
func TestTheAPIURLAgentsSeeCarriesNoCredentials(t *testing.T) {
	old := config.INFISICAL_URL
	config.INFISICAL_URL = "https://admin:s3cret@" + testInfisicalHost + "/api?token=s3cret#s3cret"
	t.Cleanup(func() { config.INFISICAL_URL = old })

	if got := proxyAPIURL(); got != "https://"+testInfisicalHost+"/api" {
		t.Fatalf("proxyAPIURL() = %q", got)
	}
	if hint := proxyErrorHint(errorCodeHostNotAllowed); strings.Contains(hint, "s3cret") || strings.Contains(hint, "admin") {
		t.Fatalf("the hint carries the credentials: %q", hint)
	}
}

func TestAnAPIURLWithCredentialsQueryOrFragmentIsNotTaken(t *testing.T) {
	for _, value := range []string{
		"https://admin:s3cret@infisical.test/api", "https://infisical.test/api?x=1", "https://infisical.test/api#x",
		"ftp://infisical.test/api", "https:///api", "https://infisical.test/a\x7fpi",
	} {
		if got := APIURLFromHeader(value); got != "" {
			t.Errorf("APIURLFromHeader(%q) = %q, want none", value, got)
		}
	}
	if got := APIURLFromHeader("https://infisical.test/api/"); got != "https://infisical.test/api" {
		t.Fatalf("APIURLFromHeader trimmed to %q", got)
	}
}

// Agents get the URL people already pass to --domain, and add /api themselves.
func TestTheAgentGetsInfisicalsURLWithoutAPI(t *testing.T) {
	for apiURL, want := range map[string]string{
		"https://app.infisical.com/api":     "https://app.infisical.com",
		"http://localhost:8080/api":         "http://localhost:8080",
		"https://example.com/infisical/api": "https://example.com/infisical",
		"https://example.com/custom":        "",
		"":                                  "",
	} {
		if got := InfisicalURL(apiURL); got != want {
			t.Errorf("InfisicalURL(%q) = %q, want %q", apiURL, got, want)
		}
	}
}
