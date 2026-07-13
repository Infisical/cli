package agentproxy

import (
	"net"
	"strings"
)

type hostPattern struct {
	host string
	port string
	path string
}

func parseHostPatterns(raw string) []hostPattern {
	var patterns []hostPattern
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		p := hostPattern{}
		if idx := strings.Index(part, "/"); idx != -1 {
			p.path = part[idx:]
			part = part[:idx]
		}
		// bracketed IPv6 ([::1] or [2001:db8::1]:8443): brackets disambiguate the port colon, and the
		// host is stored unbracketed to match the incoming hostname (parseConnectTarget strips brackets)
		if strings.HasPrefix(part, "[") {
			if end := strings.Index(part, "]"); end != -1 {
				p.host = part[1:end]
				if rest := part[end+1:]; strings.HasPrefix(rest, ":") {
					p.port = rest[1:]
				}
				patterns = append(patterns, p)
				continue
			}
		}
		if idx := strings.LastIndex(part, ":"); idx != -1 {
			p.port = part[idx+1:]
			part = part[:idx]
		}
		p.host = part
		patterns = append(patterns, p)
	}
	return patterns
}

type matchDetail struct {
	exactHost    bool
	specificPort bool
	pathLen      int
}

func (m matchDetail) betterThan(o matchDetail) bool {
	if m.exactHost != o.exactHost {
		return m.exactHost
	}
	if m.specificPort != o.specificPort {
		return m.specificPort
	}
	return m.pathLen > o.pathLen
}

func (m matchDetail) equalTo(o matchDetail) bool {
	return m.exactHost == o.exactHost && m.specificPort == o.specificPort && m.pathLen == o.pathLen
}

func (p hostPattern) match(host, port, path string) (bool, matchDetail) {
	detail := matchDetail{}

	host = strings.ToLower(host)
	patternHost := strings.ToLower(p.host)

	if strings.HasPrefix(patternHost, "*.") {
		suffix := patternHost[1:]
		// wildcard matches exactly one extra label: api.github.com yes, a.b.github.com no
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

// hostsEqual compares hosts by value when both are IP literals, so IPv6 forms like ::1 and
// 0:0:0:0:0:0:0:1 match regardless of how the pattern was written; otherwise it is a plain compare.
func hostsEqual(a, b string) bool {
	if a == b {
		return true
	}
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	return ipA != nil && ipB != nil && ipA.Equal(ipB)
}

// Full ties are broken by lexicographically-smallest service name so the winner is deterministic regardless of the unordered list-endpoint result.
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
			switch {
			case best == nil, detail.betterThan(bestDetail):
				best = svc
				bestDetail = detail
			case detail.equalTo(bestDetail) && svc.name < best.name:
				best = svc
				bestDetail = detail
			}
		}
	}
	return best
}
