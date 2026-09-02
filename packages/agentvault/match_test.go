package agentvault

import (
	"encoding/json"
	"os"
	"testing"
)

// The fixture is the shared contract with the backend grammar
// (backend/src/ee/services/agent-vault/agent-vault-host-pattern-fixture.json). The Go copy is verbatim:
// change the backend's and copy it across, never edit only one.
//
// Only the `match` and `relate` sections apply here. Rejection and normalization are the backend's job —
// the proxy never sees a pattern that did not pass write-time validation — so those sections are read by
// the Vitest suite alone.
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

// The relation section is the backend's write-time conflict rule. The proxy does not enforce it, but the
// two grammars have to agree on which patterns overlap or the rule protects nothing at runtime.
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
				// The exact host must match the wildcard, and not the other way round.
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
	// The whole point of the change: an unspecified port used to match anything, so plaintext 80 matched
	// and the credential went out unencrypted.
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

	// The exact host wins whichever order the slice is in: rung 1 sits above slice order, which is why a
	// later access bundle's exact pattern beats an earlier one's wildcard.
	if got := bestMatch([]*resolvedConnection{wildcard, exact}, "api.foo.com", "443"); got != exact {
		t.Errorf("exact should win when it is second, got %v", got)
	}
	if got := bestMatch([]*resolvedConnection{exact, wildcard}, "api.foo.com", "443"); got != exact {
		t.Errorf("exact should win when it is first, got %v", got)
	}
}

func TestBestMatchFallsBackToSliceOrder(t *testing.T) {
	// Two identical patterns can only reach here from *different* access bundles, since write-time
	// validation refuses them inside one. Slice order is resolve's ordering, which is bundle position:
	// the bundle the caller named first wins.
	first := &resolvedConnection{name: "from-first-bundle", hostPatterns: parseHostPatterns("api.foo.com")}
	second := &resolvedConnection{name: "from-second-bundle", hostPatterns: parseHostPatterns("api.foo.com")}

	if got := bestMatch([]*resolvedConnection{first, second}, "api.foo.com", "443"); got != first {
		t.Errorf("the earlier connection should win, got %v", got)
	}
}

func TestBestMatchConsidersEveryPatternOnAConnection(t *testing.T) {
	// A connection carrying both a wildcard and an exact host must be able to win on the exact one.
	broad := &resolvedConnection{name: "broad", hostPatterns: parseHostPatterns("*.foo.com")}
	both := &resolvedConnection{name: "both", hostPatterns: parseHostPatterns("*.bar.com, api.foo.com")}

	if got := bestMatch([]*resolvedConnection{broad, both}, "api.foo.com", "443"); got != both {
		t.Errorf("the connection with the exact pattern should win, got %v", got)
	}
}
