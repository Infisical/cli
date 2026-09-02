package agentvault

import (
	"errors"
	"net"
	"strings"
)

var errPrivateAddress = errors.New("address is in a private or link-local range")

// The cloud metadata endpoint first, because it is the one that turns a shared proxy into a credential
// oracle for the host it runs on.
var blockedNetworks = func() []*net.IPNet {
	cidrs := []string{
		"169.254.0.0/16", // link-local, including 169.254.169.254
		"fe80::/10",      // IPv6 link-local
		"127.0.0.0/8",    // loopback
		"::1/128",
		"10.0.0.0/8", // RFC 1918
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",      // IPv6 unique local
		"100.64.0.0/10", // carrier-grade NAT
		"192.0.0.0/24",  // IETF protocol assignments
		"198.18.0.0/15", // benchmarking
		"0.0.0.0/8",     // "this" network
		"255.255.255.255/32",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, network)
		}
	}
	return nets
}()

// isBlockedAddress reports whether an upstream address is one the proxy must never reach.
//
// This is unconditional: it does not depend on the unmatched-host policy. Under the `allow` default —
// which is the default deployment — a policy-driven block would leave the proxy as an SSRF pivot into
// its own host's metadata service and private network, reachable by any agent holding any session.
func isBlockedAddress(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// resolvesToBlockedAddress catches the DNS-rebinding shape: a name that resolves into a blocked range.
// A lookup failure is not treated as blocked — the dial will fail on its own and say something useful.
func resolvesToBlockedAddress(host string) bool {
	if isBlockedAddress(host) {
		return true
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if isBlockedAddress(addr.String()) {
			return true
		}
	}
	return false
}
