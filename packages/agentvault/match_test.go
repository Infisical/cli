package agentvault

import (
	"encoding/json"
	"os"
	"testing"
)

// The fixture is the shared contract with the backend grammar
// (backend/src/ee/services/agent-vault/agent-vault-host-pattern-fixture.json).
type matchFixture struct {
	Match []struct {
		Pattern  string `json:"pattern"`
		Host     string `json:"host"`
		Port     string `json:"port"`
		Expected bool   `json:"expected"`
		Why      string `json:"why"`
	} `json:"match"`
	Relate []struct {
		A        string `json:"a"`
		B        string `json:"b"`
		Relation string `json:"relation"`
	} `json:"relate"`
}

func loadFixture(t *testing.T) matchFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/host-pattern-fixture.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var fixture matchFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	if len(fixture.Match) == 0 {
		t.Fatal("fixture has no match cases")
	}
	return fixture
}

func TestMatchAgainstSharedFixture(t *testing.T) {
	for _, tc := range loadFixture(t).Match {
		t.Run(tc.Pattern+" vs "+tc.Host+":"+tc.Port, func(t *testing.T) {
			patterns := parseHostPatterns(tc.Pattern)
			if len(patterns) == 0 {
				t.Fatalf("pattern %q parsed to nothing", tc.Pattern)
			}

			matched := false
			for _, p := range patterns {
				if ok, _ := p.match(tc.Host, tc.Port); ok {
					matched = true
					break
				}
			}
			if matched != tc.Expected {
				t.Errorf("match(%q, %q:%q) = %v, want %v (%s)", tc.Pattern, tc.Host, tc.Port, matched, tc.Expected, tc.Why)
			}
		})
	}
}

func TestRelationsAgreeWithTheBackend(t *testing.T) {
	for _, tc := range loadFixture(t).Relate {
		t.Run(tc.A+" vs "+tc.B, func(t *testing.T) {
			a := parseHostPatterns(tc.A)[0]
			b := parseHostPatterns(tc.B)[0]

			switch tc.Relation {
			case "identical":
				if a.host != b.host || a.port != b.port {
					t.Errorf("%q and %q should normalize to the same pattern, got %+v and %+v", tc.A, tc.B, a, b)
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
					t.Errorf("%q should not cover %q", tc.A, tc.B)
				}
				if ok, _ := b.match(a.host, a.port); ok {
					t.Errorf("%q should not cover %q", tc.B, tc.A)
				}
			default:
				t.Fatalf("unknown relation %q", tc.Relation)
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
	wildcard := &resolvedConnection{name: "wildcard", hostPatterns: parseHostPatterns("*.foo.com")}
	exact := &resolvedConnection{name: "exact", hostPatterns: parseHostPatterns("api.foo.com")}

	if got := bestMatch([]*resolvedConnection{wildcard, exact}, "api.foo.com", "443"); got != exact {
		t.Errorf("exact should win when it is second, got %v", got)
	}
	if got := bestMatch([]*resolvedConnection{exact, wildcard}, "api.foo.com", "443"); got != exact {
		t.Errorf("exact should win when it is first, got %v", got)
	}
}

func TestBestMatchFallsBackToSliceOrder(t *testing.T) {
	first := &resolvedConnection{name: "from-first-bundle", hostPatterns: parseHostPatterns("api.foo.com")}
	second := &resolvedConnection{name: "from-second-bundle", hostPatterns: parseHostPatterns("api.foo.com")}

	if got := bestMatch([]*resolvedConnection{first, second}, "api.foo.com", "443"); got != first {
		t.Errorf("the earlier connection should win, got %v", got)
	}
}

func TestBestMatchConsidersEveryPatternOnAConnection(t *testing.T) {
	broad := &resolvedConnection{name: "broad", hostPatterns: parseHostPatterns("*.foo.com")}
	both := &resolvedConnection{name: "both", hostPatterns: parseHostPatterns("*.bar.com, api.foo.com")}

	if got := bestMatch([]*resolvedConnection{broad, both}, "api.foo.com", "443"); got != both {
		t.Errorf("the connection with the exact pattern should win, got %v", got)
	}
}

func TestBypassIsAnExceptionToDeny(t *testing.T) {
	ps := &proxyServer{}
	ps.setConfig(ProxyConfig{UnmatchedHost: UnmatchedDeny, BypassHosts: "docs.example.com, api.github.com"})

	github := &resolvedConnection{name: "github", hostPatterns: parseHostPatterns("api.github.com")}
	connections := []*resolvedConnection{github}

	cases := []struct {
		name      string
		host      string
		wantMatch *resolvedConnection
		wantBlock bool
	}{
		{
			name:      "bypassed and uncovered is reachable, with no credential",
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
			name:      "neither is blocked under deny",
			host:      "example.com",
			wantMatch: nil,
			wantBlock: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched := bestMatch(connections, tc.host, "443")
			if matched != tc.wantMatch {
				t.Fatalf("bestMatch(%q) = %v, want %v", tc.host, matched, tc.wantMatch)
			}

			blocked := matched == nil &&
				ps.currentConfig().UnmatchedHost == UnmatchedDeny &&
				!ps.isBypassed(tc.host, "443")
			if blocked != tc.wantBlock {
				t.Errorf("blocked = %v, want %v", blocked, tc.wantBlock)
			}
		})
	}
}
