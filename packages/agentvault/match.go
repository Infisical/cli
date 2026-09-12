package agentvault

import (
	"net"
	"strings"
)

// A pattern with no port covers every port in Agent Proxy's grammar, which lets plaintext port 80
// through with the credential attached. Defaulting to 443 keeps that from happening here.
const defaultPort = "443"

// hostPattern carries no path: paths are rejected at write time, since the matcher would compare the
// decoded path while the upstream receives the escaped one.
type hostPattern struct {
	host string
	port string
	// Whether the entry named a port itself. Only the exception list reads this: a service without one
	// has to stay on 443 or a credential would go out in the clear, but an exception carries no
	// credential, so a bare host there means the host rather than one port of it.
	portWritten bool
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
					p.portWritten = true
				}
				patterns = append(patterns, p)
				continue
			}
		}

		if idx := strings.LastIndex(part, ":"); idx != -1 {
			if port := part[idx+1:]; port != "" {
				p.port = port
				p.portWritten = true
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
func bestMatch(services []*resolvedService, host, port string) *resolvedService {
	var best *resolvedService
	var bestDetail matchDetail

	for _, svc := range services {
		// Every pattern on the service is considered, not just the first that matches, so an exact pattern
		// still wins over a wildcard on the same service.
		var svcDetail matchDetail
		matchedSvc := false
		for _, pat := range svc.hostPatterns {
			matched, detail := pat.match(host, port)
			if !matched {
				continue
			}
			if !matchedSvc || detail.betterThan(svcDetail) {
				svcDetail = detail
				matchedSvc = true
			}
		}
		if !matchedSvc {
			continue
		}
		if best == nil || svcDetail.betterThan(bestDetail) {
			best = svc
			bestDetail = svcDetail
		}
	}
	return best
}
