package agentproxy

import "testing"

func svc(name, hostPattern string) *resolvedService {
	return &resolvedService{
		name:         name,
		hostPatterns: parseHostPatterns(hostPattern),
		isEnabled:    true,
	}
}

func TestParseHostPatterns(t *testing.T) {
	patterns := parseHostPatterns("api.stripe.com, *.github.com, internal.corp.com:3000/api/*")
	if len(patterns) != 3 {
		t.Fatalf("expected 3 patterns, got %d", len(patterns))
	}
	if patterns[2].host != "internal.corp.com" || patterns[2].port != "3000" || patterns[2].path != "/api/*" {
		t.Fatalf("unexpected parse: %+v", patterns[2])
	}
}

func TestExactBeatsWildcard(t *testing.T) {
	exact := svc("exact", "api.github.com")
	wildcard := svc("wildcard", "*.github.com")
	got := bestMatch([]*resolvedService{wildcard, exact}, "api.github.com", "443", "/")
	if got == nil || got.name != "exact" {
		t.Fatalf("expected exact match to win, got %v", got)
	}
}

func TestWildcardSingleLabelOnly(t *testing.T) {
	wildcard := svc("wildcard", "*.github.com")
	if got := bestMatch([]*resolvedService{wildcard}, "api.github.com", "443", "/"); got == nil {
		t.Fatal("expected wildcard to match api.github.com")
	}
	if got := bestMatch([]*resolvedService{wildcard}, "a.b.github.com", "443", "/"); got != nil {
		t.Fatal("wildcard should not match a.b.github.com")
	}
}

func TestExactHostBeatsWildcardWithMatchingPort(t *testing.T) {
	exact := svc("exact", "api.github.com")
	wildcardWithPort := svc("wildcardWithPort", "*.github.com:443")
	got := bestMatch([]*resolvedService{wildcardWithPort, exact}, "api.github.com", "443", "/")
	if got == nil || got.name != "exact" {
		t.Fatalf("expected exact host to beat wildcard host with matching port, got %v", got)
	}
}

func TestExactHostBeatsWildcardWithLongerPath(t *testing.T) {
	exact := svc("exact", "api.github.com")
	wildcardWithPath := svc("wildcardWithPath", "*.github.com/v1/*")
	got := bestMatch([]*resolvedService{wildcardWithPath, exact}, "api.github.com", "443", "/v1/repos")
	if got == nil || got.name != "exact" {
		t.Fatalf("expected exact host to beat wildcard host with longer path, got %v", got)
	}
}

func TestPortMatching(t *testing.T) {
	withPort := svc("withPort", "internal.corp.com:3000")
	if got := bestMatch([]*resolvedService{withPort}, "internal.corp.com", "3000", "/"); got == nil {
		t.Fatal("expected match on port 3000")
	}
	if got := bestMatch([]*resolvedService{withPort}, "internal.corp.com", "443", "/"); got != nil {
		t.Fatal("should not match a different port")
	}
}

func TestLongestPathPrefixWins(t *testing.T) {
	broad := svc("broad", "api.stripe.com")
	specific := svc("specific", "api.stripe.com/v1/*")
	got := bestMatch([]*resolvedService{broad, specific}, "api.stripe.com", "443", "/v1/charges")
	if got == nil || got.name != "specific" {
		t.Fatalf("expected longest path prefix to win, got %v", got)
	}
}

func TestHostMatchingIsCaseInsensitive(t *testing.T) {
	exact := svc("exact", "API.Stripe.com")
	if got := bestMatch([]*resolvedService{exact}, "api.stripe.com", "443", "/"); got == nil {
		t.Fatal("exact host match should be case-insensitive")
	}
	wildcard := svc("wildcard", "*.GitHub.com")
	if got := bestMatch([]*resolvedService{wildcard}, "API.github.com", "443", "/"); got == nil {
		t.Fatal("wildcard host match should be case-insensitive")
	}
}

func TestTieBrokenByServiceNameRegardlessOfInputOrder(t *testing.T) {
	// two services claiming the same host tie on every specificity tier; the lexicographically
	// smaller name must win in BOTH input orders so the result never depends on fetch/slice order.
	alpha := svc("alpha", "api.stripe.com")
	bravo := svc("bravo", "api.stripe.com")

	if got := bestMatch([]*resolvedService{alpha, bravo}, "api.stripe.com", "443", "/"); got == nil || got.name != "alpha" {
		t.Fatalf("expected 'alpha' to win the tie, got %v", got)
	}
	if got := bestMatch([]*resolvedService{bravo, alpha}, "api.stripe.com", "443", "/"); got == nil || got.name != "alpha" {
		t.Fatalf("tie winner must not depend on input order, got %v", got)
	}
}

func TestNoMatch(t *testing.T) {
	s := svc("stripe", "api.stripe.com")
	if got := bestMatch([]*resolvedService{s}, "api.github.com", "443", "/"); got != nil {
		t.Fatal("expected no match for unrelated host")
	}
}

func TestDisabledServiceNotMatched(t *testing.T) {
	s := svc("stripe", "api.stripe.com")
	s.isEnabled = false
	if got := bestMatch([]*resolvedService{s}, "api.stripe.com", "443", "/"); got != nil {
		t.Fatal("disabled service should not match")
	}
}
