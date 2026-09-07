package agentvault

import (
	"net"
	"strings"
)

// The old proxied-service grammar left an empty port matching anything, so plaintext port 80 matched
// and the credential went out unencrypted.
const defaultPort = "443"

// hostPattern carries no path: paths are rejected at write time, since the matcher would compare the
// decoded path while the upstream receives the escaped one.
type hostPattern struct {
	host string
	port string
}

func parseHostPatterns(raw string) []hostPattern {
	var patterns []hostPattern
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		p := hostPattern{port: defaultPort}

		if strings.HasPrefix(part, "[") {
			if end := strings.Index(part, "]"); end != -1 {
				p.host = part[1:end]
				if rest := part[end+1:]; strings.HasPrefix(rest, ":") && rest[1:] != "" {
					p.port = rest[1:]
				}
				patterns = append(patterns, p)
				continue
			}
		}

		if idx := strings.LastIndex(part, ":"); idx != -1 {
			if port := part[idx+1:]; port != "" {
				p.port = port
			}
			part = part[:idx]
		}
		p.host = strings.TrimSuffix(part, ".")
		patterns = append(patterns, p)
	}
	return patterns
}

type matchDetail struct {
	exactHost bool
}

func (m matchDetail) betterThan(o matchDetail) bool {
	return m.exactHost && !o.exactHost
}

func (p hostPattern) match(host, port string) (bool, matchDetail) {
	detail := matchDetail{}

	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	patternHost := strings.ToLower(p.host)

	if strings.HasPrefix(patternHost, "*.") {
		suffix := patternHost[1:]
		// A wildcard matches exactly one extra label. Load-bearing rather than a syntax preference: it is what
		// makes the backend's write-time conflict rule exact.
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

	if p.port != port {
		return false, detail
	}

	return true, detail
}

func hostsEqual(a, b string) bool {
	if a == b {
		return true
	}
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	return ipA != nil && ipB != nil && ipA.Equal(ipB)
}

// The ladder is exact host, then slice order. Slice order is access bundle position, so it is not incidental.
func bestMatch(connections []*resolvedConnection, host, port string) *resolvedConnection {
	var best *resolvedConnection
	var bestDetail matchDetail

	for _, conn := range connections {
		// Every pattern on the connection is considered, not just the first that matches, so an exact pattern
		// still wins over a wildcard on the same connection.
		var connDetail matchDetail
		matchedConn := false
		for _, pat := range conn.hostPatterns {
			matched, detail := pat.match(host, port)
			if !matched {
				continue
			}
			if !matchedConn || detail.betterThan(connDetail) {
				connDetail = detail
				matchedConn = true
			}
		}
		if !matchedConn {
			continue
		}
		if best == nil || connDetail.betterThan(bestDetail) {
			best = conn
			bestDetail = connDetail
		}
	}
	return best
}
