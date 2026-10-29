package agentvault

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
)

var errPrivateDestination = errors.New("the destination is a private, loopback or link-local address")

// The same ranges the backend refuses for outbound requests (backend/src/lib/ip/ipRange.ts), plus the
// IPv4-compatible and site-local IPv6 forms, which can also carry an internal address.
var blockedPrefixes = func() []netip.Prefix {
	cidrs := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::/96",
		"::1/128",
		"100::/64",
		"2001:2::/48",
		"2001:db8::/32",
		"2002::/16",
		"64:ff9b::/96",
		"64:ff9b:1::/48",
		"fc00::/7",
		"fe80::/10",
		"fec0::/10",
		"ff00::/8",
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(cidr))
	}
	return prefixes
}()

// Prefix.Contains is false for any address with a zone, so the zone comes off first; an IPv4 address written
// as IPv6 is unwrapped so the IPv4 ranges apply to it.
func blockedDestination(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Runs on the resolved address of every socket the dialer opens, so a hostname that resolves to an internal
// address is caught however the name was written.
func guardControl(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil || blockedDestination(addrPort.Addr()) {
		return errPrivateDestination
	}
	return nil
}

func newGuardedUpstreamTransport() *http.Transport {
	transport := newUpstreamTransport()
	transport.DialContext = (&net.Dialer{Control: guardControl}).DialContext
	return transport
}
