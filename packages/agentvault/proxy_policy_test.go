package agentvault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// What the upstream actually received, so the assertions are about the wire rather than our own structs.
type echoed struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

type fixedResolver struct{ services []*resolvedService }

func (r fixedResolver) resolve(string) (*resolveResult, error) {
	return &resolveResult{SessionID: "s1", Services: r.services}, nil
}

// Stands up the whole path an agent's request takes: CONNECT to the proxy, TLS terminated by the proxy's
// own CA, policy and injection applied, then forwarded over TLS to a real upstream that echoes what it got.
// The upstream is addressed as 127.0.0.1, which is what httptest's certificate carries and what mintLeaf
// puts in an IP SAN, so both TLS legs verify and the CONNECT target the proxy dials is the upstream itself.
// Returns the client and the service's host, ready to build a URL from.
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

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}

	transport := newUpstreamTransport()
	// The proxy has to trust the httptest upstream's self-signed certificate to reach it.
	transport.TLSClientConfig = &tls.Config{RootCAs: upstreamPool}

	ps := &proxyServer{transport: transport, ca: newCaManager(key, cert)}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(fixedResolver{services: []*resolvedService{build(host)}}, ps.pollInterval)

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
	return client, host
}

func policyService(host string, methods, prefixes []string, headers []customHeader, subs []substitution) *resolvedService {
	return &resolvedService{
		name:                "github",
		accessBundleName:    "bundle",
		hostPatterns:        parseHostPatterns(host),
		allowedMethods:      toMethodSet(methods),
		allowedPathPrefixes: toPathPrefixes(prefixes),
		credential:          credential{kind: credentialPassthrough},
		headers:             headers,
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
	if !strings.Contains(body, `service "github" does not allow POST`) {
		t.Fatalf("unhelpful 403 body: %q", body)
	}
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
	// The placeholder must be gone from every surface, not merely replaced in the ones we checked.
	if strings.Contains(string(payload), "__PAT__") {
		t.Fatalf("a placeholder survived to the upstream: %s", payload)
	}
}

func TestABlockedSubstitutedPathNeverEchoesTheSecret(t *testing.T) {
	// The re-check happens after the real value is in the path, so the refusal must not quote the path:
	// the 403 body goes back to the agent and the same text goes to the proxy log.
	secret := "s3cr3t%val"
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
	// The path is authorised before substitution, so a value containing a traversal must not smuggle the
	// request out of its prefix afterwards.
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

func TestTheLogSaysWhichSurfacesWereSubstituted(t *testing.T) {
	// The logged path is always the agent's own, placeholder and all, so without this field a
	// substitution that matched nothing reads exactly like one that fired.
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
		// The agent's own placeholder, never the value it was swapped for.
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
