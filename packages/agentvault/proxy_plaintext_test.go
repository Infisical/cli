package agentvault

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// The leg an agent takes for an http:// upstream: absolute-form through the proxy, no CONNECT and no TLS
// anywhere. A service reaches this fixture only by naming its port, which is what opts it into plaintext.
func newPlaintextFixture(t *testing.T, build func(host string) *resolvedService) (*http.Client, string) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	ps := &proxyServer{transport: newUpstreamTransport()}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(fixedResolver{services: []*resolvedService{build(host)}}, ps.pollInterval)

	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)

	proxyURL, _ := url.Parse(front.URL)
	proxyURL.User = url.UserPassword(ProxyAuthUsername, "agv_tok")

	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}, host
}

func TestEverythingAServiceCarriesIsAttachedOverPlainHTTP(t *testing.T) {
	client, host := newPlaintextFixture(t, func(h string) *resolvedService {
		svc := policyService(h, nil, nil,
			[]customHeader{{name: "X-Tenant", value: []byte("acme")}},
			[]substitution{{
				placeholder: "{{PAT}}",
				surfaces:    map[string]bool{surfacePath: true},
				value:       []byte("ghp_real"),
			}},
		)
		svc.credential = credential{
			kind:         credentialBearer,
			headerName:   "Authorization",
			headerPrefix: "Bearer",
			value:        []byte("tok_real"),
		}
		return svc
	})

	status, payload := do(t, client, http.MethodGet, "http://"+host+"/repos/{{PAT}}", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", status, payload)
	}
	got := decodeEcho(t, payload)

	if auth := got.Headers["Authorization"]; len(auth) != 1 || auth[0] != "Bearer tok_real" {
		t.Errorf("Authorization = %v, want the real credential", auth)
	}
	if tenant := got.Headers["X-Tenant"]; len(tenant) != 1 || tenant[0] != "acme" {
		t.Errorf("X-Tenant = %v, want the custom header", tenant)
	}
	if got.Path != "/repos/ghp_real" {
		t.Errorf("path = %q, want the substitution applied", got.Path)
	}
}

// A custom header value carrying a placeholder is resolved from the service's substitutions on the way out,
// end to end through the proxy, so one secret can be referenced across headers.
func TestACustomHeaderValueResolvesASubstitutionOverPlainHTTP(t *testing.T) {
	client, host := newPlaintextFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, nil,
			[]customHeader{{name: "X-Signature", prefix: "v1", value: []byte("__KEY__")}},
			[]substitution{{placeholder: "__KEY__", value: []byte("s3cr3t")}},
		)
	})

	status, payload := do(t, client, http.MethodGet, "http://"+host+"/things", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", status, payload)
	}
	if sig := decodeEcho(t, payload).Headers["X-Signature"]; len(sig) != 1 || sig[0] != "v1 s3cr3t" {
		t.Errorf("X-Signature = %v, want the placeholder resolved", sig)
	}
}

// A pass-through service carries no credential, so before this it was refused for a credential it never
// had and its headers were dropped with it.
func TestAPassThroughServiceStillAddsItsHeadersOverPlainHTTP(t *testing.T) {
	client, host := newPlaintextFixture(t, func(h string) *resolvedService {
		return policyService(h, nil, nil, []customHeader{{name: "X-Tenant", value: []byte("acme")}}, nil)
	})

	status, payload := do(t, client, http.MethodGet, "http://"+host+"/things", "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", status, payload)
	}
	if tenant := decodeEcho(t, payload).Headers["X-Tenant"]; len(tenant) != 1 || tenant[0] != "acme" {
		t.Errorf("X-Tenant = %v, want the custom header", tenant)
	}
}

// Restrictions are not loosened by the upstream being plaintext.
func TestAServiceRestrictionStillHoldsOverPlainHTTP(t *testing.T) {
	client, host := newPlaintextFixture(t, func(h string) *resolvedService {
		return policyService(h, []string{"GET"}, nil, nil, nil)
	})

	status, _ := do(t, client, http.MethodDelete, "http://"+host+"/things", "")
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
}
