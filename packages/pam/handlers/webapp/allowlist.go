package webapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dnsLookupTimeout = 5 * time.Second
	dnsCacheTTL      = 30 * time.Second
)

var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
}

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// blockReason is why a URL is refused, worded for the person using the viewer.
type blockReason struct {
	message string
}

func (r *blockReason) Error() string {
	return r.message
}

var (
	errSchemeNotAllowed = &blockReason{"Only http, https, ws and wss addresses can be opened."}
	errHostNotAllowed   = &blockReason{"This host is not on the account's list of allowed hosts."}
	errAddressDenied    = &blockReason{"This host points to an address that is always blocked."}
	errHostUnresolved   = &blockReason{"The gateway could not resolve this host."}
)

type hostRule struct {
	host string
	// wildcard means host is a domain whose subdomains match, but not the domain itself.
	wildcard bool
	// port 0 means the default port of the request's scheme.
	port int
}

type allowlist struct {
	rules         []hostRule
	allowLoopback bool
	resolver      resolver

	mu    sync.Mutex
	cache map[string]cachedLookup
	now   func() time.Time
}

type cachedLookup struct {
	addrs   []netip.Addr
	expires time.Time
}

func allowLoopbackFromEnv() bool {
	return os.Getenv("INFISICAL_PAM_BROWSER_ALLOW_LOOPBACK") == "true"
}

func newAllowlist(startURL string, allowedHosts []string, allowLoopback bool, r resolver) (*allowlist, error) {
	start, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("invalid start URL: %w", err)
	}
	if start.Scheme != "http" && start.Scheme != "https" {
		return nil, fmt.Errorf("start URL scheme must be http or https")
	}
	host := normalizeHost(start.Hostname())
	if host == "" {
		return nil, fmt.Errorf("start URL has no host")
	}
	port, err := urlPort(start)
	if err != nil {
		return nil, err
	}

	rules := []hostRule{{host: host, port: port}}
	for _, entry := range allowedHosts {
		rule, err := parseHostRule(entry)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return &allowlist{
		rules:         rules,
		allowLoopback: allowLoopback,
		resolver:      r,
		cache:         make(map[string]cachedLookup),
		now:           time.Now,
	}, nil
}

func parseHostRule(entry string) (hostRule, error) {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if entry == "" {
		return hostRule{}, fmt.Errorf("empty allowed host")
	}
	host, port := entry, 0
	if strings.HasPrefix(entry, "[") && strings.HasSuffix(entry, "]") {
		host = entry[1 : len(entry)-1]
	} else if strings.HasPrefix(entry, "[") || strings.Count(entry, ":") == 1 {
		h, p, err := net.SplitHostPort(entry)
		if err != nil {
			return hostRule{}, fmt.Errorf("invalid allowed host %q: %w", entry, err)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return hostRule{}, fmt.Errorf("invalid port in allowed host %q", entry)
		}
		host, port = h, n
	}
	rule := hostRule{port: port}
	if domain, ok := strings.CutPrefix(host, "*."); ok {
		rule.wildcard = true
		host = domain
	}
	rule.host = normalizeHost(host)
	if rule.host == "" || strings.Contains(rule.host, "*") {
		return hostRule{}, fmt.Errorf("invalid allowed host %q", entry)
	}
	return rule, nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func defaultPort(scheme string) int {
	switch scheme {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	}
	return 0
}

func urlPort(u *url.URL) (int, error) {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("invalid port %q", p)
		}
		return n, nil
	}
	return defaultPort(u.Scheme), nil
}

func (r hostRule) matches(host string, port int, scheme string) bool {
	want := r.port
	if want == 0 {
		want = defaultPort(scheme)
	}
	if port != want {
		return false
	}
	if r.wildcard {
		return strings.HasSuffix(host, "."+r.host)
	}
	return host == r.host
}

// check returns nil when the browser may load rawURL, or the reason it may not.
func (a *allowlist) check(ctx context.Context, rawURL string) *blockReason {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errHostNotAllowed
	}
	switch u.Scheme {
	case "http", "https", "ws", "wss":
	default:
		return errSchemeNotAllowed
	}
	host := normalizeHost(u.Hostname())
	port, err := urlPort(u)
	if err != nil || host == "" {
		return errHostNotAllowed
	}
	allowed := false
	for _, rule := range a.rules {
		if rule.matches(host, port, u.Scheme) {
			allowed = true
			break
		}
	}
	if !allowed {
		return errHostNotAllowed
	}

	addrs, err := a.lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return errHostUnresolved
	}
	for _, addr := range addrs {
		if a.denied(addr) {
			return errAddressDenied
		}
	}
	return nil
}

func (a *allowlist) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}

	a.mu.Lock()
	cached, ok := a.cache[host]
	a.mu.Unlock()
	if ok && a.now().Before(cached.expires) {
		return cached.addrs, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	addrs, err := a.resolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no addresses")
	}

	a.mu.Lock()
	a.cache[host] = cachedLookup{addrs: addrs, expires: a.now().Add(dnsCacheTTL)}
	a.mu.Unlock()
	return addrs, nil
}

func (a *allowlist) denied(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, m := range metadataAddrs {
		if addr == m {
			return true
		}
	}
	if addr.IsLoopback() {
		return !a.allowLoopback
	}
	return addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified()
}

// hostResolverRules builds Chromium's --host-resolver-rules so that only allowed hosts resolve.
// It backs up request interception, which does not see WebSocket handshakes or service workers.
// MAP * also catches IP literals, so they need an EXCLUDE too, IPv6 ones without brackets.
func (a *allowlist) hostResolverRules() string {
	parts := []string{"MAP * ~NOTFOUND"}
	seen := make(map[string]bool)
	for _, rule := range a.rules {
		pattern := rule.host
		if rule.wildcard {
			pattern = "*." + rule.host
		}
		if seen[pattern] {
			continue
		}
		seen[pattern] = true
		parts = append(parts, "EXCLUDE "+pattern)
	}
	return strings.Join(parts, ", ")
}

// MaskURL removes the userinfo of rawURL and replaces query and fragment values with ***,
// keeping the parameter names.
func MaskURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "***"
	}
	u.User = nil
	if u.RawQuery != "" {
		u.RawQuery = maskParams(u.RawQuery)
	}
	if u.Fragment != "" {
		fragment := maskParams(u.EscapedFragment())
		u.Fragment, _ = url.PathUnescape(fragment)
		u.RawFragment = fragment
	}
	return u.String()
}

func maskParams(params string) string {
	parts := strings.Split(params, "&")
	for i, part := range parts {
		if name, _, ok := strings.Cut(part, "="); ok {
			parts[i] = name + "=***"
		}
	}
	return strings.Join(parts, "&")
}
