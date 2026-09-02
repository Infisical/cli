package agentvault

import (
	"net"
	"strings"
)

// defaultPort is what a pattern with no port means. The old proxied-service grammar left an empty port
// matching anything, so plaintext port 80 matched and the credential went out unencrypted. Defaulting to
// 443 closes that; an explicit port stays allowed, :80 included, because some internal APIs sit behind a
// non-443 TLS port — so the proxy also refuses to inject on any upstream it did not reach over TLS.
const defaultPort = "443"

// hostPattern carries no path. Paths are rejected at write time: the matcher would compare the decoded
// path while the upstream receives the escaped one, so `/v1/safe/../../admin` and `%2f` both collect a
// credential meant for `/v1/safe`.
//
// The grammar is mirrored in the backend (agent-vault-host-pattern.ts). testdata/host-pattern-fixture.json
// is the shared contract; keep the two in sync through it, not through this comment.
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

		// Bracketed IPv6 ([::1] or [2001:db8::1]:8443): the brackets disambiguate the port colon, and the
		// host is stored unbracketed to match the incoming hostname, which arrives unbracketed.
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

// matchDetail records only what can still vary. The inherited ladder had three rungs — exact host, then
// specific port, then longest path. Paths are gone and every pattern now has a concrete port, so the
// middle and last rungs can never fire: exact-beats-wildcard is the only rung left, and far more traffic
// reaches the caller-controlled tiebreak than the original design assumed.
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
		// A wildcard matches exactly one extra label: api.github.com yes, a.b.github.com no. This is
		// load-bearing rather than a syntax preference — it is what makes every pattern pair identical,
		// contained or disjoint, and therefore what makes write-time conflict detection exact.
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

// hostsEqual compares hosts by value when both are IP literals, so IPv6 forms like ::1 and
// 0:0:0:0:0:0:0:1 match regardless of how the pattern was written; otherwise it is a plain compare.
func hostsEqual(a, b string) bool {
	if a == b {
		return true
	}
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	return ipA != nil && ipB != nil && ipA.Equal(ipB)
}

// bestMatch picks the connection whose credential goes on the wire.
//
// The ladder is: exact host beats wildcard, then slice order. Slice order is not incidental — resolve
// returns connections ordered by (session bundle position, connection name), and position is the order
// the caller named their bundles at mint. Write-time validation refuses two connections in one bundle
// that share a pattern, so the name rung should never decide anything; it is here so the matcher is
// total rather than silently depending on the order rows came back from a database.
//
// There is no fallback. If the winning connection's credential comes back 401 or 403, the proxy does not
// retry with the next match: one host, one credential, one attempt.
func bestMatch(connections []*resolvedConnection, host, port string) *resolvedConnection {
	var best *resolvedConnection
	var bestDetail matchDetail

	for _, conn := range connections {
		// Every pattern on the connection is considered, not just the first that matches: a connection
		// can carry both `*.foo.com` and `api.foo.com`, and the exact one has to be able to win.
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
		// A tie goes to the connection already found, which is the earlier one in the slice.
		if best == nil || connDetail.betterThan(bestDetail) {
			best = conn
			bestDetail = connDetail
		}
	}
	return best
}
