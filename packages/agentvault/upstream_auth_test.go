package agentvault

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

type refreshCall struct {
	sessionToken   string
	serviceID      string
	hostPattern    string
	rejectedHash   string
	requiredScopes []string
}

type oauthResolver struct {
	services []*resolvedService

	mu     sync.Mutex
	calls  []refreshCall
	issue  credential
	status string
	err    error
	// Closed by the test to release refreshes held open, so concurrent 401s can be made to overlap one.
	gate chan struct{}
}

func (r *oauthResolver) resolve(string, *sessionLogGrant) (*resolveResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &resolveResult{SessionID: "s1", Services: r.services}, nil
}

func (r *oauthResolver) setServices(services ...*resolvedService) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services = services
}

func (r *oauthResolver) refreshCredential(sessionToken, serviceID, hostPattern, rejectedHash string, requiredScopes []string) (credential, string, error) {
	if r.gate != nil {
		<-r.gate
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, refreshCall{sessionToken, serviceID, hostPattern, rejectedHash, requiredScopes})
	if r.err != nil {
		return credential{}, "", r.err
	}
	return r.issue, r.status, nil
}

func (r *oauthResolver) refreshCalls() []refreshCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]refreshCall(nil), r.calls...)
}

func oauthToken(value string) credential {
	return credential{kind: credentialBearer, headerPrefix: "Bearer", value: []byte(value), refreshable: true}
}

func tokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type upstreamHit struct {
	auth string
	body string
}

type authUpstream struct {
	mu   sync.Mutex
	hits []upstreamHit
}

func (u *authUpstream) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.hits = append(u.hits, upstreamHit{auth: r.Header.Get("Authorization"), body: string(body)})
}

func (u *authUpstream) recorded() []upstreamHit {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamHit(nil), u.hits...)
}

// newPolicyFixture with an upstream the test answers for and a resolver that can refresh.
func newOAuthFixture(t *testing.T, resolver *oauthResolver, build func(host string) *resolvedService, handler func(w http.ResponseWriter, r *http.Request)) (*http.Client, string, *authUpstream) {
	t.Helper()

	up := &authUpstream{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.record(r)
		handler(w, r)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := "127.0.0.1:" + upstreamURL.Port()

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}

	transport := newUpstreamTransport()
	transport.TLSClientConfig = &tls.Config{RootCAs: upstreamPool}

	resolver.services = []*resolvedService{build(host)}
	ps := &proxyServer{transport: transport, ca: newCaManager(key, cert)}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(resolver, ps.pollInterval)

	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)

	clientPool := x509.NewCertPool()
	clientPool.AddCert(cert)
	proxyURL, _ := url.Parse(front.URL)
	proxyURL.User = url.UserPassword(ProxyAuthUsername, "agv_tok")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: clientPool},
		},
	}
	return client, host, up
}

func oauthMCPService(host string, token string) *resolvedService {
	svc := mcpService(host)
	svc.id = "svc-1"
	svc.hostPattern = host
	svc.credential = oauthToken(token)
	return svc
}

// Accepts only the token named, and answers anything else with the challenge an MCP server sends.
func acceptOnly(token string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

func doWith(t *testing.T, c *http.Client, method, target, contentType string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	return resp, string(payload)
}

func assertUpstreamAuthFailed(t *testing.T, resp *http.Response, body string) {
	t.Helper()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Values("WWW-Authenticate"); len(got) != 0 {
		t.Fatalf("the upstream's challenge reached the agent: %v", got)
	}
	if body != upstreamAuthFailedBody {
		t.Fatalf("body = %s", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type = %q", ct)
	}
}

const mcpCallBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{}}}`

func TestAn401RefreshesTheTokenAndRetriesTheSameRequestOnce(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("new-token"), status: oauthStatusConnected}
	client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService { return oauthMCPService(h, "old-token") }, acceptOnly("new-token"))

	resp, body := doWith(t, client, http.MethodPost, fmt.Sprintf("https://%s/mcp", host), "application/json", strings.NewReader(mcpCallBody))
	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("the retried request should have succeeded, got %d: %s", resp.StatusCode, body)
	}

	hits := up.recorded()
	if len(hits) != 2 {
		t.Fatalf("upstream saw %d requests, want the original and one retry", len(hits))
	}
	if hits[0].auth != "Bearer old-token" || hits[1].auth != "Bearer new-token" {
		t.Fatalf("tokens sent = %q, %q", hits[0].auth, hits[1].auth)
	}
	if hits[1].body != mcpCallBody {
		t.Fatalf("the retry carried a different body: %q", hits[1].body)
	}

	calls := resolver.refreshCalls()
	if len(calls) != 1 {
		t.Fatalf("refresh called %d times, want 1", len(calls))
	}
	if calls[0].serviceID != "svc-1" || calls[0].hostPattern != host || calls[0].sessionToken != "agv_tok" || calls[0].rejectedHash != tokenHash("old-token") || calls[0].requiredScopes != nil {
		t.Fatalf("refresh call = %+v", calls[0])
	}

	resp, _ = doWith(t, client, http.MethodGet, fmt.Sprintf("https://%s/mcp", host), "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a later request should inject the refreshed token, got %d", resp.StatusCode)
	}
	if hits := up.recorded(); hits[len(hits)-1].auth != "Bearer new-token" || len(hits) != 3 {
		t.Fatalf("the refreshed token was not swapped into the cache: %+v", hits)
	}
	if got := len(resolver.refreshCalls()); got != 1 {
		t.Fatalf("refresh called %d times after the swap, want 1", got)
	}
}

func TestAn401TwiceGivesA502WithoutTheChallenge(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("new-token")}
	client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService { return oauthMCPService(h, "old-token") }, acceptOnly("nothing"))

	resp, body := doWith(t, client, http.MethodPost, fmt.Sprintf("https://%s/mcp", host), "application/json", strings.NewReader(mcpCallBody))
	assertUpstreamAuthFailed(t, resp, body)
	if got := len(up.recorded()); got != 2 {
		t.Fatalf("upstream saw %d requests, want exactly one retry", got)
	}
	if got := len(resolver.refreshCalls()); got != 1 {
		t.Fatalf("refresh called %d times, want 1", got)
	}
}

func TestAnUnchangedTokenIsNotRetried(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("old-token"), status: "needs-reauthorization"}
	client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService { return oauthMCPService(h, "old-token") }, acceptOnly("nothing"))

	resp, body := doWith(t, client, http.MethodGet, fmt.Sprintf("https://%s/mcp", host), "", nil)
	assertUpstreamAuthFailed(t, resp, body)
	if got := len(up.recorded()); got != 1 {
		t.Fatalf("upstream saw %d requests; the same token must not be sent again", got)
	}
}

func TestANonReplayable401StillRefreshesButIsNotRetried(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("new-token")}
	client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService { return oauthMCPService(h, "old-token") }, acceptOnly("new-token"))

	// Not JSON, so the MCP inspection never buffers it, and with no length so it streams.
	stream := io.MultiReader(strings.NewReader("chunk-1"), strings.NewReader("chunk-2"))
	resp, body := doWith(t, client, http.MethodPost, fmt.Sprintf("https://%s/upload", host), "application/octet-stream", stream)
	assertUpstreamAuthFailed(t, resp, body)
	if got := len(up.recorded()); got != 1 {
		t.Fatalf("upstream saw %d requests; a streamed body cannot be replayed", got)
	}
	if got := len(resolver.refreshCalls()); got != 1 {
		t.Fatalf("refresh called %d times, want 1", got)
	}

	resp, _ = doWith(t, client, http.MethodGet, fmt.Sprintf("https://%s/mcp", host), "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the refreshed token should still be swapped in, got %d", resp.StatusCode)
	}
}

func TestARefreshFailureFallsThroughToA502(t *testing.T) {
	for name, err := range map[string]error{
		"not found":   &api.APIError{StatusCode: http.StatusNotFound, Name: "NotFound"},
		"host moved":  &api.APIError{StatusCode: http.StatusConflict, Name: "Conflict"},
		"server":      &api.APIError{StatusCode: http.StatusInternalServerError},
		"unreachable": errors.New("dial tcp: connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			resolver := &oauthResolver{err: err}
			client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService { return oauthMCPService(h, "old-token") }, acceptOnly("new-token"))

			resp, body := doWith(t, client, http.MethodGet, fmt.Sprintf("https://%s/mcp", host), "", nil)
			assertUpstreamAuthFailed(t, resp, body)
			if got := len(up.recorded()); got != 1 {
				t.Fatalf("upstream saw %d requests, want no retry", got)
			}
			if got := len(resolver.refreshCalls()); got != 1 {
				t.Fatalf("refresh called %d times, want 1", got)
			}

			doWith(t, client, http.MethodGet, fmt.Sprintf("https://%s/mcp", host), "", nil)
			if hits := up.recorded(); hits[len(hits)-1].auth != "Bearer old-token" {
				t.Fatalf("a failed refresh changed the cached token: %+v", hits)
			}
		})
	}
}

func TestInsufficientScopeIsReportedAndNotRetried(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("old-token"), status: "needs-additional-scopes"}
	client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService { return oauthMCPService(h, "old-token") },
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="issues:write  comments:write", error_description="needs \"write\""`)
			w.WriteHeader(http.StatusForbidden)
		})

	resp, body := doWith(t, client, http.MethodPost, fmt.Sprintf("https://%s/mcp", host), "application/json", strings.NewReader(mcpCallBody))
	assertUpstreamAuthFailed(t, resp, body)
	if got := len(up.recorded()); got != 1 {
		t.Fatalf("upstream saw %d requests, want no retry", got)
	}
	calls := resolver.refreshCalls()
	if len(calls) != 1 {
		t.Fatalf("refresh called %d times, want 1", len(calls))
	}
	if !reflect.DeepEqual(calls[0].requiredScopes, []string{"issues:write", "comments:write"}) || calls[0].rejectedHash != tokenHash("old-token") || calls[0].hostPattern != host {
		t.Fatalf("scope report = %+v", calls[0])
	}
}

func TestAPlain403PassesThrough(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("new-token")}
	client, host, _ := newOAuthFixture(t, resolver, func(h string) *resolvedService { return oauthMCPService(h, "old-token") },
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("not your project"))
		})

	resp, body := doWith(t, client, http.MethodGet, fmt.Sprintf("https://%s/mcp", host), "", nil)
	if resp.StatusCode != http.StatusForbidden || body != "not your project" {
		t.Fatalf("got %d: %s", resp.StatusCode, body)
	}
	if got := len(resolver.refreshCalls()); got != 0 {
		t.Fatalf("refresh called %d times for a 403 that is not about scopes", got)
	}
}

func TestANonOAuthCredentialKeepsTheUpstreams401(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("new-token")}
	client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService {
		svc := oauthMCPService(h, "static-token")
		svc.credential.refreshable = false
		return svc
	}, acceptOnly("new-token"))

	resp, body := doWith(t, client, http.MethodPost, fmt.Sprintf("https://%s/mcp", host), "application/json", strings.NewReader(mcpCallBody))
	if resp.StatusCode != http.StatusUnauthorized || body != `{"error":"invalid_token"}` {
		t.Fatalf("got %d: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("a static credential's 401 lost its challenge")
	}
	if got := len(resolver.refreshCalls()); got != 0 || len(up.recorded()) != 1 {
		t.Fatalf("a static credential was refreshed (%d) or retried (%d)", got, len(up.recorded()))
	}
}

func TestConcurrent401sShareOneRefresh(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("new-token"), gate: make(chan struct{})}
	var rejected atomic.Int32
	const agents = 8
	allRejected := make(chan struct{})
	client, host, _ := newOAuthFixture(t, resolver, func(h string) *resolvedService { return oauthMCPService(h, "old-token") },
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "Bearer new-token" {
				w.WriteHeader(http.StatusOK)
				return
			}
			if rejected.Add(1) == agents {
				close(allRejected)
			}
			w.WriteHeader(http.StatusUnauthorized)
		})

	go func() {
		<-allRejected
		close(resolver.gate)
	}()

	var wg sync.WaitGroup
	statuses := make(chan int, agents)
	for i := 0; i < agents; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/mcp", host), nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("an agent got %d, want every retry to succeed", status)
		}
	}
	if got := len(resolver.refreshCalls()); got != 1 {
		t.Fatalf("%d concurrent 401s made %d refresh calls, want 1", agents, got)
	}
}

func TestBearerChallengeParams(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   map[string]string
	}{
		{"insufficient scope", []string{`Bearer error="insufficient_scope", scope="a b"`}, map[string]string{"error": "insufficient_scope", "scope": "a b"}},
		{"token form and case", []string{`bearer Error=insufficient_scope,Scope=read`}, map[string]string{"error": "insufficient_scope", "scope": "read"}},
		{"escaped quote", []string{`Bearer error_description="say \"hi\", ok", error="invalid_token"`}, map[string]string{"error_description": `say "hi", ok`, "error": "invalid_token"}},
		{"other scheme first", []string{`Basic realm="x", Bearer error="insufficient_scope"`}, map[string]string{"error": "insufficient_scope"}},
		{"other scheme only", []string{`Basic realm="x" error="insufficient_scope"`}, map[string]string{}},
		{"second header", []string{`Basic realm="x"`, `Bearer scope="s"`}, map[string]string{"scope": "s"}},
		{"unterminated", []string{`Bearer error="insuff`}, map[string]string{"error": "insuff"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bearerChallengeParams(tc.values); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestChallengedScopesStayWithinTheBackendsLimits(t *testing.T) {
	raw := strings.Repeat("s ", maxReportedScopes+5) + strings.Repeat("x", maxReportedScopeLen+1)
	if got := challengedScopes(raw); len(got) != maxReportedScopes {
		t.Fatalf("got %d scopes, want %d", len(got), maxReportedScopes)
	}
	if got := challengedScopes("ok " + strings.Repeat("x", maxReportedScopeLen+1)); !reflect.DeepEqual(got, []string{"ok"}) {
		t.Fatalf("got %v", got)
	}
}

func TestResolveTreatsAnUnknownTypeAsHTTPAndMarksOAuthRefreshable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sessionId": "s1",
			"services": []any{
				map[string]any{"id": "a", "name": "future", "type": "websocket", "hostPattern": "a.example",
					"credential": map[string]any{"type": "bearer", "value": "t"}},
				map[string]any{"id": "b", "name": "linear", "type": "mcp", "hostPattern": "b.example",
					"credential": map[string]any{"type": "bearer", "headerName": "Authorization", "headerPrefix": "Bearer",
						"value": "t", "source": "oauth", "expiresAt": "2026-10-15T12:00:00Z"}},
				map[string]any{"id": "c", "name": "other", "type": "mcp", "hostPattern": "c.example",
					"credential": map[string]any{"type": "bearer", "value": "t", "source": "something-else"}},
			},
			"sessionLogs": map[string]any{"enabled": false},
		})
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	defer func() { config.INFISICAL_URL = old }()

	resolver, err := newInfisicalResolver(func() string { return "ptok" })
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.resolve("tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Services) != 3 {
		t.Fatalf("got %d services", len(result.Services))
	}
	future, linear, other := result.Services[0], result.Services[1], result.Services[2]
	if future.kind != serviceKindHTTP || future.credential.kind != credentialBearer || future.credential.refreshable {
		t.Fatalf("unknown type = %q, credential %+v", future.kind, future.credential)
	}
	if linear.kind != serviceKindMCP || !linear.credential.refreshable {
		t.Fatalf("oauth credential = %+v", linear.credential)
	}
	if other.credential.refreshable {
		t.Fatal("only source oauth is refreshable")
	}
}

func TestRefreshCredentialCallsTheContractEndpoint(t *testing.T) {
	var gotPath, gotSession, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotSession, gotAuth = r.URL.Path, r.Header.Get(api.AgentVaultSessionHeader), r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credential":{"type":"bearer","headerName":"Authorization","headerPrefix":"Bearer","value":"fresh","source":"oauth","expiresAt":null},"status":"connected"}`))
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	defer func() { config.INFISICAL_URL = old }()

	resolver, err := newInfisicalResolver(func() string { return "ptok" })
	if err != nil {
		t.Fatal(err)
	}
	cred, status, err := resolver.refreshCredential("tok", "svc-1", "mcp.example", tokenHash("stale"), []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/agent-vault/proxy/services/svc-1/credential-refresh" || gotSession != "tok" || gotAuth != "Bearer ptok" {
		t.Fatalf("path %q session %q auth %q", gotPath, gotSession, gotAuth)
	}
	want := map[string]any{"hostPattern": "mcp.example", "rejectedTokenHash": tokenHash("stale"), "requiredScopes": []any{"read"}}
	if !reflect.DeepEqual(gotBody, want) {
		t.Fatalf("body = %v", gotBody)
	}
	if string(cred.value) != "fresh" || !cred.refreshable || status != "connected" {
		t.Fatalf("credential %+v status %q", cred, status)
	}

	gotBody = nil
	if _, _, err := resolver.refreshCredential("tok", "svc-1", "mcp.example", tokenHash("stale"), nil); err != nil {
		t.Fatal(err)
	}
	if _, present := gotBody["requiredScopes"]; present {
		t.Fatal("a 401 refresh sent requiredScopes")
	}
	if gotBody["hostPattern"] != "mcp.example" {
		t.Fatalf("a 401 refresh sent hostPattern %v", gotBody["hostPattern"])
	}
}

// Serves resolves from a token the test sets, and can hold one resolve open so a swap lands while it runs.
type pollRaceResolver struct {
	mu      sync.Mutex
	polled  string
	holdOne chan struct{}
	entered chan struct{}
	issue   credential
}

func (r *pollRaceResolver) resolve(string, *sessionLogGrant) (*resolveResult, error) {
	r.mu.Lock()
	value, hold := r.polled, r.holdOne
	r.holdOne = nil
	r.mu.Unlock()
	if hold != nil {
		close(r.entered)
		<-hold
	}
	svc := &resolvedService{id: "svc-1", name: "linear", kind: serviceKindMCP, hostPattern: "mcp.example", credential: oauthToken(value)}
	return &resolveResult{SessionID: "s1", Services: []*resolvedService{svc}}, nil
}

func (r *pollRaceResolver) refreshCredential(string, string, string, string, []string) (credential, string, error) {
	return r.issue, oauthStatusConnected, nil
}

func (r *pollRaceResolver) setPolled(value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.polled = value
}

func injectedToken(t *testing.T, cache *sessionCache) string {
	t.Helper()
	services, err := cache.get("tok")
	if err != nil {
		t.Fatal(err)
	}
	return string(services[0].credential.value)
}

func TestAPollThatStartedBeforeASwapDoesNotRestoreTheReplacedToken(t *testing.T) {
	resolver := &pollRaceResolver{polled: "old-token", issue: oauthToken("new-token")}
	cache := newTestCache(resolver)
	if got := injectedToken(t, cache); got != "old-token" {
		t.Fatalf("seeded %q", got)
	}

	release := make(chan struct{})
	resolver.mu.Lock()
	resolver.holdOne, resolver.entered = release, make(chan struct{})
	resolver.mu.Unlock()
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		cache.refresh()
	}()
	<-resolver.entered

	old := oauthToken("old-token")
	if _, err := cache.refreshCredential("tok", "svc-1", "mcp.example", &old, nil); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-pollDone

	if got := injectedToken(t, cache); got != "new-token" {
		t.Fatalf("after a stale poll the proxy injects %q, want new-token", got)
	}

	resolver.setPolled("newer-token")
	cache.refresh()
	if got := injectedToken(t, cache); got != "newer-token" {
		t.Fatalf("a later poll's token was not taken, got %q", got)
	}
}

type scopeReportRefresher struct {
	oauthResolver
	entered chan []string
}

func (r *scopeReportRefresher) refreshCredential(sessionToken, serviceID, hostPattern, rejectedHash string, requiredScopes []string) (credential, string, error) {
	r.entered <- requiredScopes
	return r.oauthResolver.refreshCredential(sessionToken, serviceID, hostPattern, rejectedHash, requiredScopes)
}

func TestConcurrentScopeReportsEachReachInfisicalWhenTheirTokenOrScopesDiffer(t *testing.T) {
	cases := []struct {
		name   string
		token  string
		scopes []string
	}{
		{"different scopes", "tok-value", []string{"write"}},
		{"different tokens", "new-token", []string{"read"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &scopeReportRefresher{
				oauthResolver: oauthResolver{issue: oauthToken("tok-value"), gate: make(chan struct{})},
				entered:       make(chan []string, 2),
			}
			cache := newTestCache(resolver)
			sent := oauthToken("tok-value")

			var wg sync.WaitGroup
			report := func(token string, scopes []string) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					sent := oauthToken(token)
					if _, err := cache.refreshCredential("tok", "svc-1", "mcp.example", &sent, scopes); err != nil {
						t.Error(err)
					}
				}()
			}
			report(string(sent.value), []string{"read"})
			<-resolver.entered
			report(tc.token, tc.scopes)
			select {
			case <-resolver.entered:
			case <-time.After(2 * time.Second):
				close(resolver.gate)
				wg.Wait()
				t.Fatal("the second report was merged into the first one's call")
			}
			close(resolver.gate)
			wg.Wait()

			reported := map[string]bool{}
			for _, call := range resolver.refreshCalls() {
				reported[call.rejectedHash+" "+strings.Join(call.requiredScopes, " ")] = true
			}
			if !reported[tokenHash("tok-value")+" read"] || !reported[tokenHash(tc.token)+" "+strings.Join(tc.scopes, " ")] || len(reported) != 2 {
				t.Fatalf("Infisical received scope reports %v, want both token/scope pairs", reported)
			}
		})
	}
}

func TestCredentialFlightKeyIsCanonicalPerScopeSet(t *testing.T) {
	a := credentialFlightKey("k", "svc", "a.example", "hash", []string{"write", "read", "read"})
	b := credentialFlightKey("k", "svc", "a.example", "hash", []string{"read", "write"})
	if a != b {
		t.Fatalf("same scope set gave different keys: %q, %q", a, b)
	}
	if a == credentialFlightKey("k", "svc", "a.example", "hash", []string{"read"}) {
		t.Fatal("different scope sets share a key")
	}
	if credentialFlightKey("k", "svc", "a.example", "hash", nil) == credentialFlightKey("k", "svc", "a.example", "hash", []string{""}) {
		t.Fatal("a 401 refresh shares a key with a scope report")
	}
	if credentialFlightKey("k", "svc", "a.example", "hash", nil) == credentialFlightKey("k", "svc", "b.example", "hash", nil) {
		t.Fatal("refreshes for different destinations share a key")
	}
}

func TestARefreshedTokenIsDroppedWhenAPollMovedTheServiceMeanwhile(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("new-token"), gate: make(chan struct{})}
	resolver.setServices(&resolvedService{id: "svc-1", kind: serviceKindMCP, hostPattern: "a.example", credential: oauthToken("a-token")})
	cache := newTestCache(resolver)
	if got := injectedToken(t, cache); got != "a-token" {
		t.Fatalf("seeded %q", got)
	}

	sent := oauthToken("a-token")
	done := make(chan error, 1)
	go func() {
		_, err := cache.refreshCredential("tok", "svc-1", "a.example", &sent, nil)
		done <- err
	}()

	resolver.setServices(&resolvedService{id: "svc-1", kind: serviceKindMCP, hostPattern: "b.example", credential: oauthToken("b-token")})
	cache.refresh()
	close(resolver.gate)

	if err := <-done; !errors.Is(err, errServiceHostChanged) {
		t.Fatalf("err = %v, want errServiceHostChanged", err)
	}
	if got := injectedToken(t, cache); got != "b-token" {
		t.Fatalf("the proxy injects %q, want the polled b-token", got)
	}
	if calls := resolver.refreshCalls(); len(calls) != 1 || calls[0].hostPattern != "a.example" {
		t.Fatalf("refresh calls = %+v", calls)
	}
}

func TestA409FromCredentialRefreshLeavesTheCacheAlone(t *testing.T) {
	var refreshes atomic.Int32
	var gotHost atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/credential-refresh") {
			refreshes.Add(1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotHost.Store(body["hostPattern"])
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"statusCode":409,"error":"Conflict","message":"The service changed; wait for the next poll."}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sessionId": "s1",
			"services": []any{map[string]any{"id": "svc-1", "name": "linear", "type": "mcp", "hostPattern": "a.example",
				"credential": map[string]any{"type": "bearer", "headerName": "Authorization", "headerPrefix": "Bearer", "value": "a-token", "source": "oauth"}}},
			"sessionLogs": map[string]any{"enabled": false},
		})
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	defer func() { config.INFISICAL_URL = old }()

	resolver, err := newInfisicalResolver(func() string { return "ptok" })
	if err != nil {
		t.Fatal(err)
	}
	cache := newTestCache(resolver)
	if got := injectedToken(t, cache); got != "a-token" {
		t.Fatalf("seeded %q", got)
	}

	sent := oauthToken("a-token")
	_, err = cache.refreshCredential("tok", "svc-1", "a.example", &sent, nil)
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("err = %v, want the 409", err)
	}
	if got := refreshes.Load(); got != 1 {
		t.Fatalf("refresh called %d times, want 1", got)
	}
	if got := gotHost.Load(); got != "a.example" {
		t.Fatalf("hostPattern sent = %v", got)
	}
	if got := injectedToken(t, cache); got != "a-token" {
		t.Fatalf("a 409 changed the cached token to %q", got)
	}
}

func TestALateCredentialResponseKeepsThePolledCredential(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		issue  credential
		polled credential
		err    error
	}{
		{"reauthorized", nil, oauthToken("refreshed-old-token"), oauthToken("reauthorized-token"), nil},
		{"scope report", []string{"write"}, oauthToken("old-token"), oauthToken("new-token"), nil},
		{"static bearer", nil, oauthToken("refreshed-old-token"), credential{kind: credentialBearer, headerName: "X-Api-Key", value: []byte("old-token")}, errCredentialNotRefreshable},
		{"basic", nil, oauthToken("refreshed-old-token"), credential{kind: credentialBasic, username: "user", password: []byte("password")}, errCredentialNotRefreshable},
		{"passthrough", nil, oauthToken("refreshed-old-token"), credential{kind: credentialPassthrough}, errCredentialNotRefreshable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &scopeReportRefresher{
				oauthResolver: oauthResolver{issue: tc.issue, gate: make(chan struct{})},
				entered:       make(chan []string, 1),
			}
			defer func() {
				select {
				case <-resolver.gate:
				default:
					close(resolver.gate)
				}
			}()
			resolver.setServices(oauthMCPService("mcp.example", "old-token"))
			cache := newTestCache(resolver)
			injectedToken(t, cache)

			type result struct {
				cred credential
				err  error
			}
			done := make(chan result, 1)
			sent := oauthToken("old-token")
			go func() {
				cred, err := cache.refreshCredential("tok", "svc-1", "mcp.example", &sent, tc.scopes)
				done <- result{cred, err}
			}()
			<-resolver.entered

			polled := oauthMCPService("mcp.example", "unused")
			polled.credential = tc.polled
			resolver.setServices(polled)
			cache.refresh()
			close(resolver.gate)
			got := <-done
			if !errors.Is(got.err, tc.err) {
				t.Fatalf("refresh error = %v, want %v", got.err, tc.err)
			}
			if got.err == nil && !reflect.DeepEqual(got.cred, tc.polled) {
				t.Fatalf("retry credential = %+v, want the newer credential %+v", got.cred, tc.polled)
			}
			services, err := cache.get("tok")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(services[0].credential, tc.polled) {
				t.Fatalf("late response replaced the polled credential: %+v", services[0].credential)
			}
		})
	}
}

func TestALateScopeReportKeepsAConcurrentRefresh(t *testing.T) {
	resolver := &scopeReportRefresher{
		oauthResolver: oauthResolver{issue: oauthToken("old-token"), gate: make(chan struct{})},
		entered:       make(chan []string, 1),
	}
	resolver.setServices(oauthMCPService("mcp.example", "old-token"))
	cache := newTestCache(resolver)
	injectedToken(t, cache)
	sent := oauthToken("old-token")
	done := make(chan error, 1)
	go func() {
		_, err := cache.refreshCredential("tok", "svc-1", "mcp.example", &sent, []string{"write"})
		done <- err
	}()
	<-resolver.entered
	_, swapErr := cache.swapCredential(sessionKey("tok"), "svc-1", "mcp.example", credentialHash(&sent), oauthToken("new-token"))
	close(resolver.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if swapErr != nil {
		t.Fatal(swapErr)
	}
	if got := injectedToken(t, cache); got != "new-token" {
		t.Fatalf("late scope report restored %q, want new-token", got)
	}
}

func TestAPollReplacingOAuthWithStaticAuthKeepsItsCredential(t *testing.T) {
	static := &resolvedService{
		id:          "svc-1",
		hostPattern: "mcp.example",
		credential: credential{
			kind:       credentialBearer,
			headerName: "X-Api-Key",
			value:      []byte("old-token"),
		},
	}
	rejected := oauthToken("old-token")
	entry := &sessionEntry{swaps: map[string]*credentialSwap{
		"svc-1": {
			installed:   oauthToken("new-token"),
			hostPattern: "mcp.example",
			replaced:    map[string]bool{credentialHash(&rejected): true},
			gen:         1,
		},
	}}
	services := keepNewerSwaps(entry, []*resolvedService{static}, 0)
	if services[0] != static {
		t.Fatalf("a poll changing authentication was overwritten with %+v", services[0].credential)
	}
}

func TestOpenAuthErrorBodiesDoNotBlockRecovery(t *testing.T) {
	cases := []struct {
		name      string
		first     int
		retry     int
		want      int
		refreshes int
	}{
		{"401 then success", http.StatusUnauthorized, http.StatusOK, http.StatusOK, 1},
		{"401 twice", http.StatusUnauthorized, http.StatusUnauthorized, http.StatusBadGateway, 1},
		{"insufficient scope", http.StatusForbidden, 0, http.StatusBadGateway, 1},
		{"401 then insufficient scope", http.StatusUnauthorized, http.StatusForbidden, http.StatusBadGateway, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &oauthResolver{issue: oauthToken("new-token")}
			var attempts atomic.Int32
			client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService {
				return oauthMCPService(h, "old-token")
			}, func(w http.ResponseWriter, r *http.Request) {
				status := tc.first
				if attempts.Add(1) > 1 {
					status = tc.retry
				}
				if status == http.StatusOK {
					_, _ = io.WriteString(w, "ok")
					return
				}
				if status == http.StatusForbidden {
					w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="write"`)
				} else {
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				}
				w.WriteHeader(status)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			client.Timeout = 2 * time.Second
			resp, body := doWith(t, client, http.MethodGet, fmt.Sprintf("https://%s/mcp", host), "", nil)
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, tc.want, body)
			}
			if tc.want == http.StatusBadGateway {
				assertUpstreamAuthFailed(t, resp, body)
			}
			if got := len(resolver.refreshCalls()); got != tc.refreshes {
				t.Fatalf("refresh calls = %d, want %d", got, tc.refreshes)
			}
			wantAttempts := 2
			if tc.first == http.StatusForbidden {
				wantAttempts = 1
			}
			if got := len(up.recorded()); got != wantAttempts {
				t.Fatalf("upstream attempts = %d, want %d", got, wantAttempts)
			}
		})
	}
}

func TestHTTPAuthenticationKeepsUpstreamAuthResponses(t *testing.T) {
	cases := []struct {
		name string
		cred credential
		auth string
	}{
		{"bearer", credential{kind: credentialBearer, headerPrefix: "Bearer", value: []byte("static-token")}, "Bearer static-token"},
		{"custom bearer header", credential{kind: credentialBearer, headerName: "X-Api-Key", value: []byte("static-token")}, ""},
		{"basic", credential{kind: credentialBasic, username: "user", password: []byte("pass")}, "Basic dXNlcjpwYXNz"},
		{"passthrough", credential{kind: credentialPassthrough}, ""},
	}
	for _, tc := range cases {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, status), func(t *testing.T) {
				resolver := &oauthResolver{issue: oauthToken("unexpected-refresh")}
				const challenge = `Bearer error="insufficient_scope", scope="write"`
				client, host, up := newOAuthFixture(t, resolver, func(h string) *resolvedService {
					svc := oauthMCPService(h, "unused")
					svc.kind = serviceKindHTTP
					svc.credential = tc.cred
					return svc
				}, func(w http.ResponseWriter, r *http.Request) {
					if tc.cred.headerName == "X-Api-Key" && r.Header.Get("X-Api-Key") != "static-token" {
						t.Error("custom bearer header was not injected")
					}
					w.Header().Set("WWW-Authenticate", challenge)
					w.WriteHeader(status)
					_, _ = io.WriteString(w, "permission denied")
				})
				resp, body := doWith(t, client, http.MethodPost, fmt.Sprintf("https://%s/api", host), "application/json", strings.NewReader(mcpCallBody))
				if resp.StatusCode != status || body != "permission denied" || resp.Header.Get("WWW-Authenticate") != challenge {
					t.Fatalf("upstream response changed: status %d, challenge %q, body %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"), body)
				}
				if got := len(resolver.refreshCalls()); got != 0 {
					t.Fatalf("static authentication triggered %d refreshes", got)
				}
				if hits := up.recorded(); len(hits) != 1 || hits[0].auth != tc.auth || hits[0].body != mcpCallBody {
					t.Fatalf("upstream requests changed: %+v", hits)
				}
			})
		}
	}
}

func TestAnMCPEventStreamIsForwardedBeforeItCompletes(t *testing.T) {
	resolver := &oauthResolver{issue: oauthToken("unexpected-refresh")}
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	client, host, _ := newOAuthFixture(t, resolver, func(h string) *resolvedService {
		return oauthMCPService(h, "valid-token")
	}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Mcp-Session-Id", "upstream-session")
		_, _ = io.WriteString(w, "event: message\ndata: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "data: last\n\n")
		case <-r.Context().Done():
		}
	})
	client.Timeout = 2 * time.Second
	resp, err := client.Get(fmt.Sprintf("https://%s/mcp", host))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("Mcp-Session-Id") != "upstream-session" {
		t.Fatalf("event-stream response changed: %d %v", resp.StatusCode, resp.Header)
	}
	reader := bufio.NewReader(resp.Body)
	for _, want := range []string{"event: message\n", "data: first\n", "\n"} {
		if got, err := reader.ReadString('\n'); err != nil || got != want {
			t.Fatalf("streamed line = %q, err %v, want %q before the upstream finishes", got, err, want)
		}
	}
	close(release)
	if tail, err := io.ReadAll(reader); err != nil || string(tail) != "data: last\n\n" {
		t.Fatalf("stream tail = %q, err %v", tail, err)
	}
	if got := len(resolver.refreshCalls()); got != 0 {
		t.Fatalf("a successful event stream triggered %d refreshes", got)
	}
}
