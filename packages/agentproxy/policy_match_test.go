package agentproxy

import "testing"

func agentPolicy(name string, rules ...policyPattern) *resolvedAgentPolicy {
	policy := &resolvedAgentPolicy{id: name, name: name}
	for _, pattern := range rules {
		policy.rules = append(policy.rules, policyRule{pattern: pattern})
	}
	return policy
}

func userPolicy(name string, rules ...policyPattern) *resolvedUserPolicy {
	policy := &resolvedUserPolicy{id: name, name: name}
	for _, pattern := range rules {
		policy.rules = append(policy.rules, policyRule{pattern: pattern})
	}
	return policy
}

func TestParsePolicyPattern(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
		host   string
		port   string
		path   string
	}{
		{"api.slack.com", "", "api.slack.com", "", ""},
		{"https://api.slack.com/*", "https", "api.slack.com", "", "/*"},
		{"http://localhost:8080/v1/*", "http", "localhost", "8080", "/v1/*"},
		{"*.atlassian.net", "", "*.atlassian.net", "", ""},
		{"[2001:db8::1]:8443/x", "", "2001:db8::1", "8443", "/x"},
	}

	for _, tc := range cases {
		got := parsePolicyPattern(tc.raw, nil)
		if got.scheme != tc.scheme || got.host != tc.host || got.port != tc.port || got.path != tc.path {
			t.Errorf("parsePolicyPattern(%q) = %+v", tc.raw, got)
		}
	}
}

func TestPolicyPatternEnforcesScheme(t *testing.T) {
	pattern := parsePolicyPattern("https://api.slack.com/*", nil)

	if ok, _ := pattern.match("https", "api.slack.com", "443", "/chat.postMessage", "POST"); !ok {
		t.Error("expected https request to match an https rule")
	}
	// A plaintext request must not satisfy an https rule, or the credential leaves in the clear.
	if ok, _ := pattern.match("http", "api.slack.com", "80", "/chat.postMessage", "POST"); ok {
		t.Error("expected http request to be rejected by an https rule")
	}
}

func TestPolicyPatternMethods(t *testing.T) {
	anyMethod := parsePolicyPattern("api.slack.com", nil)
	if ok, _ := anyMethod.match("https", "api.slack.com", "443", "/x", "DELETE"); !ok {
		t.Error("expected an empty method list to cover every method")
	}

	readOnly := parsePolicyPattern("api.slack.com", []string{"get"})
	if ok, _ := readOnly.match("https", "api.slack.com", "443", "/x", "GET"); !ok {
		t.Error("expected GET to match a GET rule, case-insensitively")
	}
	if ok, _ := readOnly.match("https", "api.slack.com", "443", "/x", "POST"); ok {
		t.Error("expected POST to be rejected by a GET-only rule")
	}
}

func TestPolicyPatternWildcardMatchesOneLabel(t *testing.T) {
	pattern := parsePolicyPattern("*.atlassian.net", nil)

	if ok, _ := pattern.match("https", "acme.atlassian.net", "443", "/", "GET"); !ok {
		t.Error("expected one extra label to match")
	}
	if ok, _ := pattern.match("https", "a.b.atlassian.net", "443", "/", "GET"); ok {
		t.Error("expected two extra labels to be rejected")
	}
	if ok, _ := pattern.match("https", "atlassian.net", "443", "/", "GET"); ok {
		t.Error("expected the bare domain to be rejected by a wildcard rule")
	}
}

// The headline behaviour: the user side narrows the agent side, without either being a subset of the other.
func TestEvaluateUserNarrowsAgent(t *testing.T) {
	agents := []*resolvedAgentPolicy{agentPolicy("slack", parsePolicyPattern("api.slack.com", nil))}
	users := []*resolvedUserPolicy{userPolicy("read-only", parsePolicyPattern("api.slack.com", []string{"GET"}))}

	matched, matchedUser := evaluate(agents, users, "https", "api.slack.com", "443", "/conversations.list", "GET")
	if matched == nil || matchedUser == nil {
		t.Fatal("expected GET to be allowed by both sides")
	}

	matched, matchedUser = evaluate(agents, users, "https", "api.slack.com", "443", "/chat.postMessage", "POST")
	if matched == nil {
		t.Error("expected the agent side to still match a POST")
	}
	if matchedUser != nil {
		t.Error("expected the user side to reject a POST")
	}
}

func TestEvaluateWithNoUserPolicyDeniesEverything(t *testing.T) {
	agents := []*resolvedAgentPolicy{agentPolicy("slack", parsePolicyPattern("api.slack.com", nil))}

	matched, matchedUser := evaluate(agents, nil, "https", "api.slack.com", "443", "/x", "GET")
	if matched == nil {
		t.Error("expected the agent side to match")
	}
	if matchedUser != nil {
		t.Error("expected no user policy to mean nothing is allowed")
	}
}

func TestEvaluateAgentWithoutRuleForHostDenies(t *testing.T) {
	agents := []*resolvedAgentPolicy{agentPolicy("slack", parsePolicyPattern("api.slack.com", nil))}
	users := []*resolvedUserPolicy{userPolicy("wide", parsePolicyPattern("api.github.com", nil))}

	matched, matchedUser := evaluate(agents, users, "https", "api.github.com", "443", "/x", "GET")
	if matched != nil {
		t.Error("expected no agent policy to match a host it has no rule for")
	}
	if matchedUser == nil {
		t.Error("expected the user side to match its own host")
	}
}

// Specificity picks the winner, which is what decides whose credential is injected.
func TestEvaluatePrefersMoreSpecificAgentPolicy(t *testing.T) {
	wildcard := agentPolicy("wildcard", parsePolicyPattern("*.example.com", nil))
	exact := agentPolicy("exact", parsePolicyPattern("api.example.com", nil))
	users := []*resolvedUserPolicy{userPolicy("all", parsePolicyPattern("*.example.com", nil))}

	matched, matchedUser := evaluate([]*resolvedAgentPolicy{wildcard, exact}, users, "https", "api.example.com", "443", "/", "GET")
	if matchedUser == nil || matched == nil {
		t.Fatal("expected a match")
	}
	if matched.name != "exact" {
		t.Errorf("expected the exact-host policy to win, got %q", matched.name)
	}
}

// The user policy reported to the activity feed is the most specific one, same as the agent side.
func TestEvaluatePrefersMoreSpecificUserPolicy(t *testing.T) {
	agents := []*resolvedAgentPolicy{agentPolicy("wide", parsePolicyPattern("*.example.com", nil))}
	users := []*resolvedUserPolicy{
		userPolicy("wildcard", parsePolicyPattern("*.example.com", nil)),
		userPolicy("exact", parsePolicyPattern("api.example.com", nil)),
	}

	_, matchedUser := evaluate(agents, users, "https", "api.example.com", "443", "/", "GET")
	if matchedUser == nil {
		t.Fatal("expected a user policy to match")
	}
	if matchedUser.name != "exact" {
		t.Errorf("expected the exact-host user policy to win, got %q", matchedUser.name)
	}
}

func TestAgentCoversHostIgnoresMethodAndPath(t *testing.T) {
	// At CONNECT time only host and port are known, so a method-restricted rule must still open the tunnel.
	agents := []*resolvedAgentPolicy{
		agentPolicy("slack", parsePolicyPattern("api.slack.com/chat.*", []string{"POST"})),
	}

	if !agentCoversHost(agents, "api.slack.com", "443") {
		t.Error("expected the host to be covered regardless of method and path")
	}
	if agentCoversHost(agents, "api.github.com", "443") {
		t.Error("expected an unrelated host not to be covered")
	}
}

func TestHostAllowed(t *testing.T) {
	entries := []string{"registry.npmjs.org", "*.pypi.org"}

	if !hostAllowed(entries, "registry.npmjs.org") {
		t.Error("expected an exact allowlist entry to match")
	}
	if !hostAllowed(entries, "files.pypi.org") {
		t.Error("expected a wildcard allowlist entry to match")
	}
	if hostAllowed(entries, "api.slack.com") {
		t.Error("expected an unlisted host not to match")
	}
}

func TestSessionTokenParsing(t *testing.T) {
	// http://<token>@host:port produces Basic with the token as the username and no password.
	if token, ok := sessionToken("Basic aXN0X2FiYzo="); !ok || token != "ist_abc" {
		t.Errorf("expected the username to be used as the token, got %q ok=%v", token, ok)
	}
	if token, ok := sessionToken("Bearer ist_abc"); !ok || token != "ist_abc" {
		t.Errorf("expected a bearer token, got %q ok=%v", token, ok)
	}
	if _, ok := sessionToken(""); ok {
		t.Error("expected an empty header to be rejected")
	}
	if _, ok := sessionToken("Basic !!!not-base64"); ok {
		t.Error("expected malformed base64 to be rejected")
	}
}
