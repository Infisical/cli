package webapp

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type fakeResolver struct {
	addrs map[string][]string
	calls atomic.Int32
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	raw, ok := f.addrs[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, a := range raw {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func publicResolver() *fakeResolver {
	return &fakeResolver{addrs: map[string][]string{
		"grafana.internal":     {"10.0.0.5"},
		"example.com":          {"10.0.0.6"},
		"a.example.com":        {"10.0.0.7"},
		"deep.a.example.com":   {"10.0.0.8"},
		"api.internal":         {"10.0.0.9"},
		"metadata.internal":    {"169.254.169.254"},
		"metadata6.internal":   {"fd00:ec2::254"},
		"loopback.internal":    {"127.0.0.1"},
		"loopback6.internal":   {"::1"},
		"linklocal.internal":   {"169.254.10.1"},
		"linklocal6.internal":  {"fe80::1"},
		"multicast.internal":   {"224.0.0.1"},
		"multicast6.internal":  {"ff02::1"},
		"unspecified.internal": {"0.0.0.0"},
		"mixed.internal":       {"10.0.0.10", "169.254.169.254"},
		"mapped.internal":      {"::ffff:169.254.169.254"},
	}}
}

func mustAllowlist(t *testing.T, start string, hosts []string, loopback bool, r resolver) *allowlist {
	t.Helper()
	a, err := newAllowlist(start, hosts, loopback, r)
	if err != nil {
		t.Fatalf("newAllowlist: %v", err)
	}
	return a
}

func TestAllowlistMatching(t *testing.T) {
	a := mustAllowlist(t, "https://grafana.internal/login", []string{"*.example.com", "API.internal:8443"}, false, publicResolver())

	cases := []struct {
		url  string
		want *blockReason
	}{
		{"https://grafana.internal/", nil},
		{"https://grafana.internal:443/d/abc", nil},
		{"wss://grafana.internal/api/live", nil},
		{"http://grafana.internal/", errHostNotAllowed},
		{"https://grafana.internal:8443/", errHostNotAllowed},
		{"https://GRAFANA.internal./", nil},
		{"https://a.example.com/", nil},
		{"https://deep.a.example.com/", nil},
		{"http://a.example.com/", nil},
		{"ws://a.example.com/", nil},
		{"https://a.example.com:8443/", errHostNotAllowed},
		{"https://example.com/", errHostNotAllowed},
		{"https://badexample.com/", errHostNotAllowed},
		{"https://api.internal:8443/", nil},
		{"http://api.internal:8443/", nil},
		{"https://api.internal/", errHostNotAllowed},
		{"ftp://grafana.internal/", errSchemeNotAllowed},
		{"file:///etc/passwd", errSchemeNotAllowed},
		{"javascript:alert(1)", errSchemeNotAllowed},
		{"data:text/html,hi", errSchemeNotAllowed},
		{"https://other.internal/", errHostNotAllowed},
	}
	for _, tc := range cases {
		if got := a.check(context.Background(), tc.url); got != tc.want {
			t.Errorf("check(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestAllowlistHTTPStartURLDefaultsToPort80(t *testing.T) {
	a := mustAllowlist(t, "http://grafana.internal", nil, false, publicResolver())
	if got := a.check(context.Background(), "http://grafana.internal:80/x"); got != nil {
		t.Errorf("port 80 refused: %v", got)
	}
	if got := a.check(context.Background(), "https://grafana.internal/"); got != errHostNotAllowed {
		t.Errorf("port 443 = %v, want host not allowed", got)
	}
}

func TestAllowlistAlwaysDeniedAddresses(t *testing.T) {
	hosts := []string{
		"metadata.internal", "metadata6.internal", "loopback.internal", "loopback6.internal",
		"linklocal.internal", "linklocal6.internal", "multicast.internal", "multicast6.internal",
		"unspecified.internal", "mixed.internal", "mapped.internal",
		"169.254.169.254", "[fd00:ec2::254]", "127.0.0.1", "[::1]", "0.0.0.0",
	}
	a := mustAllowlist(t, "https://grafana.internal", hosts, false, publicResolver())
	urls := []string{
		"https://metadata.internal/", "https://metadata6.internal/", "https://loopback.internal/",
		"https://loopback6.internal/", "https://linklocal.internal/", "https://linklocal6.internal/",
		"https://multicast.internal/", "https://multicast6.internal/", "https://unspecified.internal/",
		"https://mixed.internal/", "https://mapped.internal/",
		"https://169.254.169.254/latest/meta-data", "https://[fd00:ec2::254]/", "https://127.0.0.1/",
		"https://[::1]/", "https://0.0.0.0/",
	}
	for _, u := range urls {
		if got := a.check(context.Background(), u); got != errAddressDenied {
			t.Errorf("check(%q) = %v, want address denied", u, got)
		}
	}
}

func TestAllowlistLoopbackOptIn(t *testing.T) {
	hosts := []string{"loopback.internal", "metadata.internal", "linklocal.internal", "127.0.0.1:8080"}
	a := mustAllowlist(t, "https://grafana.internal", hosts, true, publicResolver())
	for _, u := range []string{"https://loopback.internal/", "http://127.0.0.1:8080/"} {
		if got := a.check(context.Background(), u); got != nil {
			t.Errorf("check(%q) with loopback allowed = %v", u, got)
		}
	}
	for _, u := range []string{"https://metadata.internal/", "https://linklocal.internal/"} {
		if got := a.check(context.Background(), u); got != errAddressDenied {
			t.Errorf("check(%q) with loopback allowed = %v, want address denied", u, got)
		}
	}
}

func TestAllowLoopbackFromEnv(t *testing.T) {
	t.Setenv("INFISICAL_PAM_BROWSER_ALLOW_LOOPBACK", "true")
	if !allowLoopbackFromEnv() {
		t.Error("true not honored")
	}
	t.Setenv("INFISICAL_PAM_BROWSER_ALLOW_LOOPBACK", "1")
	if allowLoopbackFromEnv() {
		t.Error("only the exact value true may allow loopback")
	}
}

func TestAllowlistDNSErrorBlocks(t *testing.T) {
	a := mustAllowlist(t, "https://missing.internal", nil, false, publicResolver())
	if got := a.check(context.Background(), "https://missing.internal/"); got != errHostUnresolved {
		t.Errorf("unresolvable host = %v, want unresolved", got)
	}
}

func TestAllowlistCachesLookups(t *testing.T) {
	r := publicResolver()
	a := mustAllowlist(t, "https://grafana.internal", nil, false, r)
	now := time.Unix(1000, 0)
	a.now = func() time.Time { return now }

	for range 3 {
		if got := a.check(context.Background(), "https://grafana.internal/"); got != nil {
			t.Fatalf("check = %v", got)
		}
	}
	if n := r.calls.Load(); n != 1 {
		t.Fatalf("lookups = %d, want 1", n)
	}
	now = now.Add(dnsCacheTTL + time.Second)
	a.check(context.Background(), "https://grafana.internal/")
	if n := r.calls.Load(); n != 2 {
		t.Fatalf("lookups after TTL = %d, want 2", n)
	}
}

func TestNewAllowlistRejectsBadInput(t *testing.T) {
	cases := []struct {
		start string
		hosts []string
	}{
		{"ftp://grafana.internal", nil},
		{"https://", nil},
		{"https://grafana.internal", []string{""}},
		{"https://grafana.internal", []string{"host:0"}},
		{"https://grafana.internal", []string{"host:70000"}},
		{"https://grafana.internal", []string{"host:abc"}},
		{"https://grafana.internal", []string{"*"}},
		{"https://grafana.internal", []string{"a.*.com"}},
	}
	for _, tc := range cases {
		if _, err := newAllowlist(tc.start, tc.hosts, false, publicResolver()); err == nil {
			t.Errorf("newAllowlist(%q, %q) succeeded", tc.start, tc.hosts)
		}
	}
}

func TestHostResolverRules(t *testing.T) {
	a := mustAllowlist(t, "https://grafana.internal:3000", []string{"*.example.com", "api.internal:8443", "api.internal", "10.0.0.1", "[fd00::1]:8080"}, false, publicResolver())
	want := "MAP * ~NOTFOUND, EXCLUDE grafana.internal, EXCLUDE *.example.com, EXCLUDE api.internal, EXCLUDE 10.0.0.1, EXCLUDE fd00::1"
	if got := a.hostResolverRules(); got != want {
		t.Errorf("hostResolverRules() = %q, want %q", got, want)
	}
}

func TestMaskURL(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@grafana.internal/d/abc?orgId=1&token=secret#tab=x&flag": "https://grafana.internal/d/abc?orgId=***&token=***#tab=***&flag",
		"https://grafana.internal/path":                                            "https://grafana.internal/path",
		"https://grafana.internal/?flag":                                           "https://grafana.internal/?flag",
		"https://grafana.internal/#access=abc123":                                  "https://grafana.internal/#access=***",
	}
	for in, want := range cases {
		if got := MaskURL(in); got != want {
			t.Errorf("MaskURL(%q) = %q, want %q", in, got, want)
		}
	}
}
