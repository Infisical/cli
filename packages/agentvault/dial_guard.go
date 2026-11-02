package agentvault

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
)

var errPrivateDestination = errors.New("the destination is a private or internal address")

// The ranges the backend refuses for outbound requests (backend/src/lib/ip/ipRange.ts), plus the IPv4-compatible
// and site-local IPv6 forms, which can also carry an internal address, and the rest of IANA's IPv6 blocks that
// aren't globally reachable. IPv4-mapped and NAT64 addresses are judged by the IPv4 address they carry instead.
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
		"100:0:0:1::/64",
		"2001::/23",
		"2001:db8::/32",
		"2002::/16",
		"3fff::/20",
		"5f00::/16",
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

// The RFC 6052 well-known prefix. On an IPv6-only host with DNS64 every IPv4-only site resolves into it, so
// blocking the whole prefix would refuse the public internet.
var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// Prefix.Contains is false for any address with a zone, so the zone comes off first; an IPv4 address written
// as IPv6 is unwrapped so the IPv4 ranges apply to it.
func blockedDestination(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	if nat64Prefix.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// The machine's own addresses: a cloud host often has its public address on an interface, and a connection
// to it lands on the machine itself, past any cloud firewall in front of it.
func hostAddresses() map[netip.Addr]bool {
	own := map[netip.Addr]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return own
	}
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			own[prefix.Addr().WithZone("").Unmap()] = true
		}
	}
	return own
}

// Runs on the resolved address of every socket the dialer opens, so a hostname that resolves to an internal
// address is caught however the name was written.
func guardControl(own map[netip.Addr]bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		addrPort, err := netip.ParseAddrPort(address)
		if err != nil {
			return errPrivateDestination
		}
		ip := addrPort.Addr()
		if blockedDestination(ip) || own[ip.WithZone("").Unmap()] {
			return errPrivateDestination
		}
		return nil
	}
}

func newGuardedUpstreamTransport() *http.Transport {
	transport := newUpstreamTransport()
	transport.DialContext = (&net.Dialer{Control: guardControl(hostAddresses())}).DialContext
	return transport
}
