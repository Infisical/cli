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

// matchScore returns (matched, score). Higher score = more specific match.
// Scoring: exact host (2) vs wildcard (1); specific port (+2) vs any (0); + path prefix length.
func (p hostPattern) matchScore(host, port, path string) (bool, int) {
	score := 0

	if strings.HasPrefix(p.host, "*.") {
		suffix := p.host[1:] // ".github.com"
		// wildcard matches exactly one extra label: api.github.com yes, a.b.github.com no
		if !strings.HasSuffix(host, suffix) {
			return false, 0
		}
		prefix := strings.TrimSuffix(host, suffix)
		if prefix == "" || strings.Contains(prefix, ".") {
			return false, 0
		}
		score += 1
	} else {
		if !strings.EqualFold(p.host, host) {
			return false, 0
		}
		score += 2
	}

	if p.port != "" {
		if p.port != port {
			return false, 0
		}
		score += 2
	}

	if p.path != "" {
		prefix := strings.TrimSuffix(p.path, "*")
		if !strings.HasPrefix(path, prefix) {
			return false, 0
		}
		score += len(prefix)
	}

	return true, score
}

// bestMatch picks the highest-scoring service for the target. On ties, the first service
// (definition order) wins because callers iterate services in order and use strict ">".
func bestMatch(services []*resolvedService, host, port, path string) *resolvedService {
	var best *resolvedService
	bestScore := -1

	for _, svc := range services {
		if !svc.isEnabled {
			continue
		}
		for _, pat := range svc.hostPatterns {
			matched, score := pat.matchScore(host, port, path)
			if matched && score > bestScore {
				bestScore = score
				best = svc
			}
		}
	}
	return best
}
