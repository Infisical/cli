package agentvault

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern  string
		host     string
		port     string
		expected bool
		why      string
	}{
		{"api.github.com", "api.github.com", "443", true, "exact host, default port"},
		{"api.github.com", "API.GitHub.com", "443", true, "case-insensitive"},
		{"api.github.com", "api.github.com.", "443", true, "trailing dot"},
		{"api.github.com", "api.github.com", "80", false, "portless means 443"},
		{"api.github.com", "api.github.com", "8443", false, "443 is concrete"},
		{"api.github.com:8443", "api.github.com", "8443", true, "explicit port"},
		{"api.github.com", "other.github.com", "443", false, "not a sibling"},
		{"*.github.com", "api.github.com", "443", true, "one label"},
		{"*.github.com", "a.b.github.com", "443", false, "not any depth"},
		{"*.github.com", "github.com", "443", false, "a label is required"},
		{"*.github.com", "evilgithub.com", "443", false, "the dot matters"},
		{"*.bar.foo.com", "api.foo.com", "443", false, "label counts differ"},
		{"[::1]", "0:0:0:0:0:0:0:1", "443", true, "IPv6 expanded"},
		{"[0:0:0:0:0:0:0:1]:8200", "::1", "8200", true, "written the long way"},
		{"[2001:db8::1]", "2001:db8::2", "443", false, "different addresses"},
		{"10.0.1.5:8200", "10.0.1.5", "8200", true, "IPv4 literal"},
		{"[::ffff:192.0.2.1]", "192.0.2.1", "443", true, "IPv4-mapped IPv6"},
		{"192.0.2.1", "::ffff:192.0.2.1", "443", true, "and the other way round"},
		{"api.github.com, registry.npmjs.org", "registry.npmjs.org", "443", true, "a column is a set"},
	}

	for _, tc := range cases {
		t.Run(tc.pattern+" vs "+tc.host+":"+tc.port, func(t *testing.T) {
			patterns := parseHostPatterns(tc.pattern)
			if len(patterns) == 0 {
				t.Fatalf("pattern %q parsed to nothing", tc.pattern)
			}

			matched := false
			for _, p := range patterns {
				if ok, _ := p.match(tc.host, tc.port); ok {
					matched = true
					break
				}
			}
			if matched != tc.expected {
				t.Errorf("match(%q, %q:%q) = %v, want %v (%s)", tc.pattern, tc.host, tc.port, matched, tc.expected, tc.why)
			}
		})
	}
}

// The relations the backend's write-time conflict rule is built on. The proxy does not enforce that
// rule, but the two grammars have to agree on which patterns overlap.
func TestPatternRelations(t *testing.T) {
	cases := []struct {
		a, b     string
		relation string
	}{
		{"api.foo.com", "api.foo.com", "identical"},
		{"api.foo.com", "api.foo.com:443", "identical"},
		{"api.foo.com", "*.foo.com", "contained"},
		{"*.foo.com", "api.foo.com", "contained"},
		{"*.foo.com", "*.bar.foo.com", "disjoint"},
		{"api.foo.com:443", "api.foo.com:8443", "disjoint"},
		{"*.foo.com", "api.foo.com:8443", "disjoint"},
		{"api.foo.com", "api.bar.com", "disjoint"},
	}

	for _, tc := range cases {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			a := parseHostPatterns(tc.a)[0]
			b := parseHostPatterns(tc.b)[0]

			switch tc.relation {
			case "identical":
				if a.host != b.host || a.port != b.port {
					t.Errorf("%q and %q should normalize to the same pattern, got %+v and %+v", tc.a, tc.b, a, b)
				}
			case "contained":
				wildcard, exact := a, b
				if !isWildcard(a) {
					wildcard, exact = b, a
				}
				if ok, _ := wildcard.match(exact.host, exact.port); !ok {
					t.Errorf("%q should cover %q", wildcard.host, exact.host)
				}
				if ok, _ := exact.match(wildcard.host, wildcard.port); ok {
					t.Errorf("%q must not cover %q", exact.host, wildcard.host)
				}
			case "disjoint":
				if ok, _ := a.match(b.host, b.port); ok {
					t.Errorf("%q should not cover %q", tc.a, tc.b)
				}
				if ok, _ := b.match(a.host, a.port); ok {
					t.Errorf("%q should not cover %q", tc.b, tc.a)
				}
			default:
				t.Fatalf("unknown relation %q", tc.relation)
			}
		})
	}
}

func isWildcard(p hostPattern) bool {
	return len(p.host) > 2 && p.host[0] == '*' && p.host[1] == '.'
}

func TestPortlessPatternDefaultsTo443(t *testing.T) {
	p := parseHostPatterns("api.github.com")[0]
	if p.port != defaultPort {
		t.Fatalf("portless pattern got port %q, want %q", p.port, defaultPort)
	}
	if ok, _ := p.match("api.github.com", "80"); ok {
		t.Error("a portless pattern must not match plaintext port 80")
	}
}

func TestBestMatchPrefersExactOverWildcard(t *testing.T) {
	wildcard := &resolvedService{name: "wildcard", hostPatterns: parseHostPatterns("*.foo.com")}
	exact := &resolvedService{name: "exact", hostPatterns: parseHostPatterns("api.foo.com")}

	if got := bestMatch([]*resolvedService{wildcard, exact}, "api.foo.com", "443"); got != exact {
		t.Errorf("exact should win when it is second, got %v", got)
	}
	if got := bestMatch([]*resolvedService{exact, wildcard}, "api.foo.com", "443"); got != exact {
		t.Errorf("exact should win when it is first, got %v", got)
	}
}

func TestBestMatchFallsBackToSliceOrder(t *testing.T) {
	first := &resolvedService{name: "from-first-bundle", hostPatterns: parseHostPatterns("api.foo.com")}
	second := &resolvedService{name: "from-second-bundle", hostPatterns: parseHostPatterns("api.foo.com")}

	if got := bestMatch([]*resolvedService{first, second}, "api.foo.com", "443"); got != first {
		t.Errorf("the earlier service should win, got %v", got)
	}
}

func TestBestMatchConsidersEveryPatternOnAService(t *testing.T) {
	broad := &resolvedService{name: "broad", hostPatterns: parseHostPatterns("*.foo.com")}
	both := &resolvedService{name: "both", hostPatterns: parseHostPatterns("*.bar.com, api.foo.com")}

	if got := bestMatch([]*resolvedService{broad, both}, "api.foo.com", "443"); got != both {
		t.Errorf("the service with the exact pattern should win, got %v", got)
	}
}

func TestExceptionOverridesBundleHostsPolicy(t *testing.T) {
	ps := &proxyServer{}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, AllowedHosts: "docs.example.com, api.github.com, pkg.example.com:8080"})

	github := &resolvedService{name: "github", hostPatterns: parseHostPatterns("api.github.com")}
	services := []*resolvedService{github}

	cases := []struct {
		name      string
		host      string
		wantMatch *resolvedService
		wantBlock bool
	}{
		{
			name:      "an exception that no service covers is reachable, with no credential",
			host:      "docs.example.com",
			wantMatch: nil,
			wantBlock: false,
		},
		{
			name:      "covered wins, so the credential is still attached",
			host:      "api.github.com",
			wantMatch: github,
			wantBlock: false,
		},
		{
			name:      "neither is blocked under bundle-hosts",
			host:      "example.com",
			wantMatch: nil,
			wantBlock: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched := bestMatch(services, tc.host, "443")
			if matched != tc.wantMatch {
				t.Fatalf("bestMatch(%q) = %v, want %v", tc.host, matched, tc.wantMatch)
			}

			if blocked := ps.blocksOffBundle(matched, tc.host, "443"); blocked != tc.wantBlock {
				t.Errorf("blocked = %v, want %v", blocked, tc.wantBlock)
			}
		})
	}
}

// An exception carries no credential, so a bare host there means the host rather than one port of
// it. An entry that names a port keeps meaning only that port.
func TestExceptionPortScope(t *testing.T) {
	ps := &proxyServer{}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, AllowedHosts: "docs.example.com, [::1], pkg.example.com:8080"})

	for _, tc := range []struct {
		host, port string
		want       bool
		why        string
	}{
		{"docs.example.com", "443", true, "a bare host over https"},
		{"docs.example.com", "80", true, "and over plain http, which used to be blocked"},
		{"docs.example.com", "9000", true, "and on any other port"},
		{"::1", "80", true, "a bare ipv6 literal is no different"},
		{"pkg.example.com", "8080", true, "the port that was written"},
		{"pkg.example.com", "443", false, "naming a port still scopes the entry to it"},
		{"other.example.com", "80", false, "a host that is not on the list"},
	} {
		if got := ps.isAllowedHost(tc.host, tc.port); got != tc.want {
			t.Errorf("isAllowedHost(%q, %q) = %v, want %v: %s", tc.host, tc.port, got, tc.want, tc.why)
		}
	}
}
