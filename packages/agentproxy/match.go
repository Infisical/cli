package agentproxy

import (
	"strings"
)

// hostPattern is a single parsed pattern from a proxied service's comma-separated hostPattern.
type hostPattern struct {
	host string // may start with "*." for a wildcard
	port string // "" means any port
	path string // "" means any path; may end with "*"
}

func parseHostPatterns(raw string) []hostPattern {
	var patterns []hostPattern
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		p := hostPattern{}
		// split off path
		if idx := strings.Index(part, "/"); idx != -1 {
			p.path = part[idx:]
			part = part[:idx]
		}
		// split off port
		if idx := strings.LastIndex(part, ":"); idx != -1 {
			p.port = part[idx+1:]
			part = part[:idx]
		}
		p.host = part
		patterns = append(patterns, p)
	}
	return patterns
}

// matchDetail records how specifically a pattern matched, for tiered precedence comparison.
type matchDetail struct {
	exactHost    bool // exact host match (vs wildcard)
	specificPort bool // pattern pinned a port (vs any-port)
	pathLen      int  // length of the matched path prefix
}

// betterThan reports whether m is strictly more specific than o, per the documented precedence:
// 1. exact host beats wildcard; 2. specific port beats any-port; 3. longest path prefix.
// Each tier is only consulted when all higher tiers are equal.
func (m matchDetail) betterThan(o matchDetail) bool {
	if m.exactHost != o.exactHost {
		return m.exactHost
	}
	if m.specificPort != o.specificPort {
		return m.specificPort
	}
	return m.pathLen > o.pathLen
}

// match reports whether the pattern matches the target and, if so, how specifically.
func (p hostPattern) match(host, port, path string) (bool, matchDetail) {
	detail := matchDetail{}

	// Hostnames are case-insensitive; fold both sides so wildcard matching agrees with exact matching.
	host = strings.ToLower(host)
	patternHost := strings.ToLower(p.host)

	if strings.HasPrefix(patternHost, "*.") {
		suffix := patternHost[1:] // ".github.com"
		// wildcard matches exactly one extra label: api.github.com yes, a.b.github.com no
		if !strings.HasSuffix(host, suffix) {
			return false, detail
		}
		prefix := strings.TrimSuffix(host, suffix)
		if prefix == "" || strings.Contains(prefix, ".") {
			return false, detail
		}
	} else {
		if patternHost != host {
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

// bestMatch picks the most specific matching service per the tiered precedence in betterThan.
// On full ties, the first service (definition order) wins because betterThan is strict.
func bestMatch(services []*resolvedService, host, port, path string) *resolvedService {
	var best *resolvedService
	var bestDetail matchDetail

	for _, svc := range services {
		if !svc.isEnabled {
			continue
		}
		for _, pat := range svc.hostPatterns {
			matched, detail := pat.match(host, port, path)
			if !matched {
				continue
			}
			if best == nil || detail.betterThan(bestDetail) {
				best = svc
				bestDetail = detail
			}
		}
	}
	return best
}
