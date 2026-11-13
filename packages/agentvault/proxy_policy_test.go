package agentvault

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type echoed struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

type fixedResolver struct{ services []*resolvedService }

func (r fixedResolver) resolve(string, *sessionLogGrant) (*resolveResult, error) {
	return &resolveResult{SessionID: "s1", Services: r.services}, nil
}

// The whole path an agent's request takes: CONNECT, TLS terminated by the proxy's own CA, policy and
// injection applied, then forwarded to a real upstream that echoes what it got. The upstream is addressed as
// 127.0.0.1 so both TLS legs verify against httptest's certificate and mintLeaf's IP SAN.
func newPolicyFixture(t *testing.T, build func(host string) *resolvedService) (*http.Client, string) {
	t.Helper()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(echoed{
			Method:  r.Method,
			Path:    r.URL.EscapedPath(),
			Query:   r.URL.RawQuery,
			Headers: r.Header,
			Body:    string(body),
		})
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := "127.0.0.1:" + upstreamURL.Port()

	_, client := newTLSProxy(t, upstream, fixedResolver{services: []*resolvedService{build(host)}})
	return client, host
}

// The proxy in front of a TLS upstream, and a client that goes through it: the proxy trusts the upstream's
// certificate and the client trusts the proxy's CA. The proxy is returned so a test can set it up further
// before its first request.
func newTLSProxy(t *testing.T, upstream *httptest.Server, resolver sessionResolver) (*proxyServer, *http.Client) {
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
	return ps, client
}

func policyService(host string, methods, prefixes []string, customHeaders []customHeader, subs []substitution) *resolvedService {
	return &resolvedService{
		name:                "github",
		accessBundleName:    "bundle",
		hostPatterns:        parseHostPatterns(host),
		allowedMethods:      toMethodSet(methods),
		allowedPathPrefixes: toPathPrefixes(prefixes),
		credential:          credential{kind: credentialPassthrough},
		customHeaders:       customHeaders,
		substitutions:       subs,
	}
}

func do(t *testing.T, c *http.Client, method, target, body string) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(payload))
}

func decodeEcho(t *testing.T, payload string) echoed {
	t.Helper()
	var got echoed
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("upstream did not echo JSON (%v): %s", err, payload)
	}
	return got
}

func TestMethodPolicyThroughTheTunnel(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, []string{"GET"}, nil, nil, nil)
	})

	status, body := do(t, client, "GET", fmt.Sprintf("https://%s/anything", host), "")
	if status != http.StatusOK {
		t.Fatalf("GET should reach the upstream, got %d: %s", status, body)
	}
	if got := decodeEcho(t, body); got.Method != "GET" {
		t.Fatalf("upstream saw %q", got.Method)
	}

	status, body = do(t, client, "POST", fmt.Sprintf("https://%s/anything", host), "x")
	if status != http.StatusForbidden {
		t.Fatalf("POST should be refused, got %d: %s", status, body)
	}
	if refusal := decodeProxyError(t, body); !strings.Contains(refusal.Message, `service "github" does not allow POST`) || refusal.Error != errorCodePolicyBlocked {
		t.Fatalf("unhelpful 403 body: %q", body)
	}
}

func decodeProxyError(t *testing.T, body string) proxyErrorBody {
	t.Helper()
	var refusal proxyErrorBody
	if err := json.Unmarshal([]byte(body), &refusal); err != nil {
		t.Fatalf("the proxy's own error should be JSON, got %q: %v", body, err)
	}
	return refusal
}

func TestPathPolicyThroughTheTunnel(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, []string{"/repos"}, nil, nil)
	})

	status, body := do(t, client, "GET", fmt.Sprintf("https://%s/repos/octo/hello", host), "")
	if status != http.StatusOK {
		t.Fatalf("an allowed path should reach the upstream, got %d: %s", status, body)
	}

	for _, path := range []string{"/repositories", "/admin", "/repos/%2e%2e/admin"} {
		status, body = do(t, client, "GET", fmt.Sprintf("https://%s%s", host, path), "")
		if status != http.StatusForbidden {
			t.Fatalf("%s should be refused, got %d: %s", path, status, body)
		}
		if !strings.Contains(body, "blocked by service policy") {
			t.Fatalf("%s: unhelpful 403 body: %q", path, body)
		}
	}
}

func TestCustomHeadersReachTheUpstream(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, nil, []customHeader{
			{name: "X-Org-Id", value: []byte("acme")},
			{name: "X-Api-Ver", prefix: "v", value: []byte("2")},
		}, nil)
	})

	status, body := do(t, client, "GET", fmt.Sprintf("https://%s/x", host), "")
	if status != http.StatusOK {
		t.Fatalf("got %d: %s", status, body)
	}
	got := decodeEcho(t, body)
	if v := got.Headers["X-Org-Id"]; len(v) != 1 || v[0] != "acme" {
		t.Fatalf("X-Org-Id = %v", v)
	}
	if v := got.Headers["X-Api-Ver"]; len(v) != 1 || v[0] != "v 2" {
		t.Fatalf("X-Api-Ver = %v", v)
	}
}

func TestSubstitutionsReachTheUpstream(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, nil, nil, []substitution{
			subOn("__PAT__", "real-token", surfacePath, surfaceQuery, surfaceHeader, surfaceBody),
		})
	})

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("https://%s/repos/__PAT__/x?key=__PAT__", host),
		strings.NewReader(`{"token":"__PAT__"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Key", "Bearer __PAT__")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d: %s", resp.StatusCode, payload)
	}

	got := decodeEcho(t, strings.TrimSpace(string(payload)))
	if got.Path != "/repos/real-token/x" {
		t.Fatalf("path = %q", got.Path)
	}
	if got.Query != "key=real-token" {
		t.Fatalf("query = %q", got.Query)
	}
	if v := got.Headers["X-Key"]; len(v) != 1 || v[0] != "Bearer real-token" {
		t.Fatalf("X-Key = %v", v)
	}
	if got.Body != `{"token":"real-token"}` {
		t.Fatalf("body = %q", got.Body)
	}
	if strings.Contains(string(payload), "__PAT__") {
		t.Fatalf("a placeholder survived to the upstream: %s", payload)
	}
}

func TestABlockedSubstitutedPathNeverEchoesTheSecret(t *testing.T) {
	secret := "../s3cr3tadmin"
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, []string{"/repos"}, nil, []substitution{
			subOn("__PAT__", secret, surfacePath),
		})
	})

	status, body := do(t, client, "GET", fmt.Sprintf("https://%s/repos/__PAT__", host), "")
	if status != http.StatusForbidden {
		t.Fatalf("expected a 403, got %d: %s", status, body)
	}
	if strings.Contains(body, "s3cr3t") {
		t.Fatalf("the 403 body handed the injected secret back to the agent: %q", body)
	}
}

func TestAPathSubstitutionIsRecheckedAgainstThePolicy(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, []string{"/repos"}, nil, []substitution{
			subOn("__PAT__", "../admin", surfacePath),
		})
	})

	status, body := do(t, client, "GET", fmt.Sprintf("https://%s/repos/__PAT__", host), "")
	if status != http.StatusForbidden {
		t.Fatalf("a substitution that escapes the prefix should be refused, got %d: %s", status, body)
	}
}

func TestASubstitutedValueCannotWalkOutOfItsPrefix(t *testing.T) {
	for _, secret := range []string{`\admin`, `;x`, `/admin`} {
		t.Run(secret, func(t *testing.T) {
			client, host := newPolicyFixture(t, func(h string) *resolvedService {
				return policyService(h, nil, []string{"/repos"}, nil, []substitution{
					subOn("__P__", secret, surfacePath),
				})
			})

			status, body := do(t, client, "GET", fmt.Sprintf("https://%s/repos/..__P__/admin", host), "")
			if status != http.StatusForbidden {
				t.Fatalf("expected a 403, got %d: %s", status, body)
			}
		})
	}
}

func TestAPathSubstitutionMayCarryASlashUnderAPrefix(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, []string{"/api/v4/projects"}, nil, []substitution{
			subOn("__PROJ__", "mygroup/myproject", surfacePath),
		})
	})

	status, body := do(t, client, "GET", fmt.Sprintf("https://%s/api/v4/projects/__PROJ__/pipelines", host), "")
	if status != http.StatusOK {
		t.Fatalf("expected a 200, got %d: %s", status, body)
	}
	if got := decodeEcho(t, strings.TrimSpace(body)); got.Path != "/api/v4/projects/mygroup%2Fmyproject/pipelines" {
		t.Fatalf("upstream path = %q", got.Path)
	}
}

func TestACustomHeaderCannotReplaceTheCredential(t *testing.T) {
	cases := []struct {
		name          string
		cred          credential
		customHeaders []customHeader
		wantHeader    string
		want          string
	}{
		{
			name:          "the default Authorization, collided case-insensitively",
			cred:          credential{kind: credentialBearer, headerPrefix: "Bearer", value: []byte("real-token")},
			customHeaders: []customHeader{{name: "authorization", value: []byte("spoofed")}},
			wantHeader:    "Authorization",
			want:          "Bearer real-token",
		},
		{
			name:          "a credential on its own header name",
			cred:          credential{kind: credentialBearer, headerName: "X-Org-Id", value: []byte("real-token")},
			customHeaders: []customHeader{{name: "X-Org-Id", value: []byte("spoofed")}},
			wantHeader:    "X-Org-Id",
			want:          "real-token",
		},
		{
			name:          "pass-through leaves the custom header alone",
			cred:          credential{kind: credentialPassthrough},
			customHeaders: []customHeader{{name: "Authorization", prefix: "Bearer", value: []byte("custom")}},
			wantHeader:    "Authorization",
			want:          "Bearer custom",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, host := newPolicyFixture(t, func(h string) *resolvedService {
				svc := policyService(h, nil, nil, tc.customHeaders, nil)
				svc.credential = tc.cred
				return svc
			})

			status, body := do(t, client, "GET", fmt.Sprintf("https://%s/x", host), "")
			if status != http.StatusOK {
				t.Fatalf("got %d: %s", status, body)
			}
			got := decodeEcho(t, strings.TrimSpace(body))
			if v := got.Headers[tc.wantHeader]; len(v) != 1 || v[0] != tc.want {
				t.Fatalf("%s = %v, want %q", tc.wantHeader, v, tc.want)
			}
			if strings.Contains(body, "spoofed") {
				t.Fatalf("the custom header replaced the credential: %s", body)
			}
		})
	}
}

func TestTheLogSaysWhichSurfacesWereSubstituted(t *testing.T) {
	type line struct {
		Path        string   `json:"path"`
		Decision    string   `json:"decision"`
		Substituted []string `json:"substituted"`
	}

	capture := func(t *testing.T, target string) line {
		t.Helper()
		client, host := newPolicyFixture(t, func(h string) *resolvedService {
			return policyService(h, nil, nil, nil, []substitution{
				subOn("__PAT__", "real-token", surfacePath, surfaceHeader),
			})
		})

		var buf bytes.Buffer
		restore := log.Logger
		log.Logger = zerolog.New(&buf)
		defer func() { log.Logger = restore }()

		if status, body := do(t, client, "GET", fmt.Sprintf("https://%s%s", host, target), ""); status != http.StatusOK {
			t.Fatalf("got %d: %s", status, body)
		}

		var got line
		for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var candidate line
			if json.Unmarshal([]byte(raw), &candidate) == nil && candidate.Decision != "" {
				got = candidate
			}
		}
		if got.Decision == "" {
			t.Fatalf("no request line logged: %s", buf.String())
		}
		return got
	}

	t.Run("a substitution that fired names its surfaces", func(t *testing.T) {
		got := capture(t, "/repos/__PAT__/x")
		if len(got.Substituted) != 1 || got.Substituted[0] != surfacePath {
			t.Fatalf("substituted = %v, want [path]", got.Substituted)
		}
		if got.Path != "/repos/__PAT__/x" {
			t.Fatalf("path = %q", got.Path)
		}
		if strings.Contains(got.Path, "real-token") {
			t.Fatalf("the log leaked the substituted value: %q", got.Path)
		}
	})

	t.Run("a substitution that matched nothing says nothing", func(t *testing.T) {
		got := capture(t, "/repos/no-placeholder-here")
		if len(got.Substituted) != 0 {
			t.Fatalf("substituted = %v, want empty", got.Substituted)
		}
	})
}

func TestAnEchoingMethodIsRefusedWhateverItsCase(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, nil, nil, nil)
	})

	// Unrestricted on methods, so only the echo guard can refuse these. Go sends the method verbatim.
	for _, method := range []string{"TRACE", "trace", "TRACK", "track"} {
		status, body := do(t, client, method, fmt.Sprintf("https://%s/anything", host), "")
		if status != http.StatusForbidden {
			t.Fatalf("%s should be refused, got %d: %s", method, status, body)
		}
		if !strings.Contains(body, "echoes headers back") {
			t.Fatalf("%s: unhelpful body %q", method, body)
		}
	}
}

func TestAMethodOverrideHeaderCannotOutrankTheAllowlist(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, []string{"GET", "POST"}, nil, nil, nil)
	})

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/anything", host), strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	req.Header.Set("X-Method-Override", "DELETE")
	req.Header.Set("X-HTTP-Method", "DELETE")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the POST itself is allowed, got %d: %s", resp.StatusCode, raw)
	}

	got := decodeEcho(t, string(raw))
	for _, name := range []string{"X-Http-Method-Override", "X-Method-Override", "X-Http-Method"} {
		if v := got.Headers[name]; len(v) > 0 {
			t.Fatalf("%s reached the upstream as %v, so the allowlist can be outranked", name, v)
		}
	}
}

func TestAnInjectedMethodOverrideCannotOutrankTheAllowlist(t *testing.T) {
	client, host := newPolicyFixture(t, func(h string) *resolvedService {
		return policyService(h, []string{"GET", "POST"}, nil, []customHeader{
			{name: "X-HTTP-Method-Override", value: []byte("DELETE")},
		}, nil)
	})

	status, body := do(t, client, "POST", fmt.Sprintf("https://%s/anything", host), "x")
	if status != http.StatusOK {
		t.Fatalf("the POST itself is allowed, got %d: %s", status, body)
	}

	got := decodeEcho(t, body)
	if v := got.Headers["X-Http-Method-Override"]; len(v) > 0 {
		t.Fatalf("the service's own header reached the upstream as %v, so the allowlist can be outranked", v)
	}
}

// An echoing TLS upstream that counts what reaches it, behind a proxy whose one service has a hook and carries a
// credential, a custom header and a substitution, none of which the hook may see.
func newHookedPolicyFixture(t *testing.T, fake *fakeHook) (*proxyServer, *http.Client, string, *atomic.Int64) {
	t.Helper()
	hits := &atomic.Int64{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(echoed{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Headers: r.Header, Body: string(body)})
	}))
	t.Cleanup(upstream.Close)
	host := strings.TrimPrefix(upstream.URL, "https://")

	svc := policyService(host, nil, nil, []customHeader{{name: "X-Tenant", value: []byte("tenant-value-secret")}},
		[]substitution{{placeholder: "{{KEY}}", surfaces: map[string]bool{surfaceBody: true, surfaceHeader: true}, value: []byte("substituted-value-secret")}})
	svc.id, svc.accessBundleID = "svc-1", "bundle-1"
	svc.credential = credential{kind: credentialBearer, headerName: "Authorization", headerPrefix: "Bearer", value: []byte("credential-value-secret")}
	svc.hook = fake.hook()

	ps, client := newTLSProxy(t, upstream, grantingResolver{services: []*resolvedService{svc}})
	ps.opts.ProxyID = "proxy-1"
	ps.sessionLogs = newSessionLogRecorder("proxy-1", &fakeShipper{})
	ps.usage = newUsageReporter((&recordingSender{}).send)
	return ps, client, host, hits
}

func doHooked(t *testing.T, client *http.Client, method, target string, body io.Reader, header http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		req.Header[name] = values
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	return resp, strings.TrimSpace(string(payload))
}

func TestAnAllowedRequestIsSentWithItsCredentialAndTheHookSawOnlyTheAgentsRequest(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	ps, client, host, _ := newHookedPolicyFixture(t, fake)

	resp, body := doHooked(t, client, http.MethodPost, "https://"+host+"/v1/Refunds?limit=2", strings.NewReader("amount={{KEY}}"),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "X-Agent": {"a", "b"}, "X-Key": {"{{KEY}}"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	got := decodeEcho(t, body)
	if got.Headers["Authorization"][0] != "Bearer credential-value-secret" || got.Body != "amount=substituted-value-secret" {
		t.Fatalf("the upstream got %+v", got)
	}

	hit := fake.only(t)
	for _, secret := range []string{"credential-value-secret", "tenant-value-secret", "substituted-value-secret"} {
		if bytes.Contains(hit.body, []byte(secret)) {
			t.Fatalf("the hook payload holds %q: %s", secret, hit.body)
		}
	}
	p := hit.payload(t)
	_, port, _ := strings.Cut(host, ":")
	want := hookPayloadRequest{Method: "POST", Scheme: "https", Host: "127.0.0.1", Port: port, Path: "/v1/Refunds", Query: "limit=2",
		Body: "amount={{KEY}}", BodyEncoding: "utf8"}
	gotReq := *p.Request
	gotReq.Headers = nil
	if !reflect.DeepEqual(gotReq, want) {
		t.Fatalf("request = %+v, want %+v", gotReq, want)
	}
	if h := p.Request.Headers; strings.Join(h["x-agent"], ",") != "a,b" || h["x-key"][0] != "{{KEY}}" || h["proxy-authorization"] != nil || h["authorization"] != nil || h["x-tenant"] != nil {
		t.Fatalf("headers = %v", h)
	}
	if p.Version != "1" || p.Proxy.ID != "proxy-1" || p.Session.ID != "s1" || p.MCP != nil || p.Connection != nil {
		t.Fatalf("payload = %s", hit.body)
	}
	if p.Service != (hookPayloadService{ID: "svc-1", Name: "github", Type: "http", AccessBundle: p.Service.AccessBundle}) ||
		p.Service.AccessBundle == nil || *p.Service.AccessBundle != (hookPayloadBundle{ID: "bundle-1", Name: "bundle"}) {
		t.Fatalf("service = %s", hit.body)
	}

	if rec := drainOneRecord(t, ps.sessionLogs); rec.Hook != nil || rec.Decision != decisionBrokered {
		t.Fatalf("an allowed request's record = %s", recordJSON(t, rec))
	}
	if got := ps.usage.brokered.Load(); got != 1 {
		t.Fatalf("a brokered request counted %d times for billing, want 1", got)
	}
}

func TestAHookDenialReachesTheAgent(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"deny","message":"Asked Ana, retry in a minute.","reason":"over budget"}`))
	ps, client, host, hits := newHookedPolicyFixture(t, fake)
	logs := captureLogs(t)

	resp, body := doHooked(t, client, http.MethodGet, "https://"+host+"/v1/charges", nil, nil)
	if resp.StatusCode != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("status %d, upstream hits %d: %s", resp.StatusCode, hits.Load(), body)
	}
	if resp.Header.Get(HeaderDecision) != decisionBlocked || resp.Header.Get(HeaderError) != errorCodeHookDenied {
		t.Fatalf("headers = %v", resp.Header)
	}
	refusal := decodeProxyError(t, body)
	if refusal.Error != errorCodeHookDenied || refusal.Message != "Asked Ana, retry in a minute." || refusal.Hint != proxyErrorHints[errorCodeHookDenied] {
		t.Fatalf("body = %s", body)
	}

	if got := ps.usage.brokered.Load(); got != 0 {
		t.Fatalf("a request the hook denied counted %d times for billing, want 0", got)
	}

	rec := drainOneRecord(t, ps.sessionLogs)
	if rec.Decision != decisionBlocked || rec.Status != http.StatusForbidden || rec.Hook == nil || rec.Hook.Decision != hookDeny ||
		rec.Hook.Reason != "over budget" || rec.Hook.DeliveryID == "" {
		t.Fatalf("record = %s", recordJSON(t, rec))
	}
	line := logs.String()
	if !strings.Contains(line, `"hook":"deny"`) || !strings.Contains(line, `"hookReason":"over budget"`) || !strings.Contains(line, `"deliveryId":"`+rec.Hook.DeliveryID+`"`) ||
		!strings.Contains(line, `"hookMs":`) || !strings.Contains(line, `"hookUrl":"`+fake.server.URL+`"`) || strings.Contains(line, "/agent-vault/hook") {
		t.Fatalf("log = %s", line)
	}
}

func TestAHookDenialWithNoMessageGetsTheDefault(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"deny"}`))
	_, client, host, _ := newHookedPolicyFixture(t, fake)
	_, body := doHooked(t, client, http.MethodGet, "https://"+host+"/", nil, nil)
	if refusal := decodeProxyError(t, body); refusal.Message != hookDeniedRequestMessage {
		t.Fatalf("body = %s", body)
	}
}

func TestEveryHookFailureRefusesTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer http.HandlerFunc
		cause  string
	}{
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }, "status_502"},
		{"redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/x", http.StatusFound) }, hookCauseRedirect},
		{"not JSON", answerHook(`ok`), hookCauseInvalidJSON},
		{"bad decision", answerHook(`{"decision":"yes"}`), hookCauseBadDecision},
		{"too large", answerHook(strings.Repeat(" ", maxHookAnswer+1)), hookCauseTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeHook(t, tc.answer)
			ps, client, host, hits := newHookedPolicyFixture(t, fake)
			resp, body := doHooked(t, client, http.MethodPost, "https://"+host+"/", strings.NewReader("x"), nil)
			if resp.StatusCode != http.StatusServiceUnavailable || hits.Load() != 0 {
				t.Fatalf("status %d, upstream hits %d", resp.StatusCode, hits.Load())
			}
			if resp.Header.Get("Retry-After") != "5" || resp.Header.Get(HeaderError) != errorCodeHookFailed || resp.Header.Get(HeaderDecision) != decisionError {
				t.Fatalf("headers = %v", resp.Header)
			}
			var fields map[string]any
			_ = json.Unmarshal([]byte(body), &fields)
			if len(fields) != 3 || fields["error"] != errorCodeHookFailed || fields["message"] != hookFailedRequestMessage || fields["hint"] != proxyErrorHints[errorCodeHookFailed] {
				t.Fatalf("body = %s", body)
			}
			rec := drainOneRecord(t, ps.sessionLogs)
			if rec.Decision != decisionError || rec.Hook == nil || rec.Hook.Decision != hookFailed || rec.Hook.Cause != tc.cause {
				t.Fatalf("record = %s", recordJSON(t, rec))
			}
		})
	}
}

func TestLargeAndCompressedBodiesReachTheHookCutAndTheUpstreamWhole(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	_, client, host, _ := newHookedPolicyFixture(t, fake)

	big := strings.Repeat("é", 1<<20)
	resp, body := doHooked(t, client, http.MethodPost, "https://"+host+"/upload", strings.NewReader(big), nil)
	if resp.StatusCode != http.StatusOK || decodeEcho(t, body).Body != big {
		t.Fatalf("status %d, the upstream did not get the whole 2 MB body", resp.StatusCode)
	}
	p := fake.only(t).payload(t).Request
	if !p.BodyTruncated || p.BodyEncoding != "utf8" || len(p.Body) != maxHookBodyPrefix || !utf8.ValidString(p.Body) {
		t.Fatalf("truncated %v, encoding %s, %d bytes", p.BodyTruncated, p.BodyEncoding, len(p.Body))
	}

	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	_, _ = zw.Write([]byte("compressed body"))
	_ = zw.Close()
	resp, _ = doHooked(t, client, http.MethodPost, "https://"+host+"/upload", bytes.NewReader(zipped.Bytes()), http.Header{"Content-Encoding": {"gzip"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	calls := fake.calls()
	p = calls[len(calls)-1].payload(t).Request
	if decoded, _ := base64.StdEncoding.DecodeString(p.Body); p.BodyEncoding != "base64" || p.BodyTruncated || !bytes.Equal(decoded, zipped.Bytes()) {
		t.Fatalf("a gzip body reached the hook as %s %q", p.BodyEncoding, p.Body)
	}
}

func TestTheProxysOwnRefusalsComeBeforeTheHook(t *testing.T) {
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	ps, client, host, _ := newHookedPolicyFixture(t, fake)
	services, _ := ps.cache.get("agv_tok")
	services[0].allowedMethods = toMethodSet([]string{"GET"})

	if resp, _ := doHooked(t, client, http.MethodDelete, "https://"+host+"/", nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := len(fake.calls()); got != 0 {
		t.Fatalf("the hook was asked about a request the policy refused (%d calls)", got)
	}
}
