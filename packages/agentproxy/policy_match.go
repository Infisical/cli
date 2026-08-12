package agentproxy

import (
	"strings"
)

// policyPattern is a rule's host pattern plus the methods it covers. It is deliberately separate from
// hostPattern (used by proxied services), which carries no scheme and no method.
type policyPattern struct {
	scheme  string
	host    string
	port    string
	path    string
	methods []string
}

// parsePolicyPattern accepts [scheme://]host[:port][/path*]. An unset scheme matches either scheme; a
// set one is enforced, so a rule naming https never lets a plaintext request carry the credential.
func parsePolicyPattern(raw string, methods []string) policyPattern {
	p := policyPattern{methods: normalizeMethods(methods)}

	part := strings.TrimSpace(raw)
	if idx := strings.Index(part, "://"); idx != -1 {
		p.scheme = strings.ToLower(part[:idx])
		part = part[idx+3:]
	}

	if idx := strings.Index(part, "/"); idx != -1 {
		p.path = part[idx:]
		part = part[:idx]
	}

	// Bracketed IPv6 ([::1] or [2001:db8::1]:8443): the brackets disambiguate the port colon, and the host
	// is stored unbracketed to match the incoming hostname.
	if strings.HasPrefix(part, "[") {
		if end := strings.Index(part, "]"); end != -1 {
			p.host = part[1:end]
			if rest := part[end+1:]; strings.HasPrefix(rest, ":") {
				p.port = rest[1:]
			}
			return p
		}
	}

	if idx := strings.LastIndex(part, ":"); idx != -1 {
		p.port = part[idx+1:]
		part = part[:idx]
	}
	p.host = part
	return p
}

func normalizeMethods(methods []string) []string {
	if len(methods) == 0 {
		return nil
	}
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// coversMethod reports whether the rule covers this HTTP method. No methods means every method, which is
// how the UI's "Any" is stored.
func (p policyPattern) coversMethod(method string) bool {
	if len(p.methods) == 0 {
		return true
	}
	method = strings.ToUpper(method)
	for _, m := range p.methods {
		if m == method {
			return true
		}
	}
	return false
}

func (p policyPattern) match(scheme, host, port, path, method string) (bool, matchDetail) {
	detail := matchDetail{}

	if p.scheme != "" && p.scheme != strings.ToLower(scheme) {
		return false, detail
	}
	if !p.coversMethod(method) {
		return false, detail
	}

	host = strings.ToLower(host)
	patternHost := strings.ToLower(p.host)

	if strings.HasPrefix(patternHost, "*.") {
		suffix := patternHost[1:]
		// The wildcard matches exactly one extra label: api.github.com yes, a.b.github.com no.
		if !strings.HasSuffix(host, suffix) {
			return false, detail
		}
		prefix := strings.TrimSuffix(host, suffix)
		if prefix == "" || strings.Contains(prefix, ".") {
			return false, detail
		}
	} else {
		if !hostsEqual(patternHost, host) {
			return false, detail
		}
		detail.exactHost = true
	}

	if p.port != "" {
		if p.port != port {
			return false, detail
		}
		detail.specificPort = true
	}

	if p.path != "" {
		prefix := strings.TrimSuffix(p.path, "*")
		if !strings.HasPrefix(path, prefix) {
			return false, detail
		}
		detail.pathLen = len(prefix)
	}

	return true, detail
}

// hostAllowed reports whether a bare host allowlist entry covers this host. Allowlist entries pass
// through with no credential, so they carry no scheme, port, path or method.
func hostAllowed(entries []string, host string) bool {
	for _, entry := range entries {
		pattern := parsePolicyPattern(entry, nil)
		if ok, _ := pattern.match("", host, "", "/", ""); ok {
			return true
		}
	}
	return false
}

type policyRule struct {
	pattern policyPattern
}

type resolvedAgentPolicy struct {
	id          string
	name        string
	rules       []policyRule
	credentials []resolvedCredential
}

type resolvedUserPolicy struct {
	id    string
	name  string
	rules []policyRule
}

// evaluate applies the intersection: a request is allowed when it matches at least one rule on an agent
// policy AND at least one rule on a user policy. Neither side is a subset of the other, so this is a
// per-request check, not set arithmetic. The winning agent policy is the most specific match, which is
// what decides whose credentials get injected. The user side picks its winner the same way even though
// only its existence gates the request, so the pair reported to the activity feed is comparable.
func evaluate(
	agentPolicies []*resolvedAgentPolicy,
	userPolicies []*resolvedUserPolicy,
	scheme, host, port, path, method string,
) (matched *resolvedAgentPolicy, matchedUser *resolvedUserPolicy) {
	var bestAgent, bestUser matchDetail

	for _, policy := range agentPolicies {
		for _, rule := range policy.rules {
			ok, detail := rule.pattern.match(scheme, host, port, path, method)
			if !ok {
				continue
			}
			switch {
			case matched == nil, detail.betterThan(bestAgent):
				matched, bestAgent = policy, detail
			case detail.equalTo(bestAgent) && policy.name < matched.name:
				matched, bestAgent = policy, detail
			}
		}
	}

	for _, policy := range userPolicies {
		for _, rule := range policy.rules {
			ok, detail := rule.pattern.match(scheme, host, port, path, method)
			if !ok {
				continue
			}
			switch {
			case matchedUser == nil, detail.betterThan(bestUser):
				matchedUser, bestUser = policy, detail
			case detail.equalTo(bestUser) && policy.name < matchedUser.name:
				matchedUser, bestUser = policy, detail
			}
		}
	}

	return matched, matchedUser
}

// agentCoversHost reports whether any agent rule could match this host at all, ignoring method and path.
// CONNECT carries only host and port, so this is what decides whether to open the tunnel; the real
// decision is made per request inside it, once the method and path are known.
func agentCoversHost(agentPolicies []*resolvedAgentPolicy, host, port string) bool {
	for _, policy := range agentPolicies {
		for _, rule := range policy.rules {
			hostOnly := policyPattern{scheme: "", host: rule.pattern.host, port: rule.pattern.port}
			if ok, _ := hostOnly.match("", host, port, "/", ""); ok {
				return true
			}
		}
	}
	return false
}
