package agentvault

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestBlockedDestination(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		blocked bool
	}{
		{"10.0.0.1", true},
		{"172.16.5.4", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"168.63.129.16", true},
		{"168.63.129.17", false},
		{"100.64.0.1", true},
		{"169.254.169.254", true},
		{"192.0.0.1", true},
		{"198.18.0.1", true},
		{"224.0.0.1", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"::", true},
		{"::1", true},
		{"fe80::1", true},
		{"fe80::1%eth0", true},
		{"fc00::1", true},
		{"fd00:ec2::254", true},
		{"fec0::1", true},
		{"ff02::1", true},
		{"::ffff:169.254.169.254", true},
		{"::169.254.169.254", true},
		{"64:ff9b::a9fe:a9fe", true},
		{"64:ff9b::a9fe:a9fe%1", true},
		{"64:ff9b:1::1", true},
		{"2002:a9fe:a9fe::1", true},
		{"2001:10::1", true},
		{"3fff::1", true},
		{"5f00::1", true},
		{"100:0:0:1::1", true},
		{"64:ff9b::a00:1", true},
		{"64:ff9b::808:808", false},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
		{"::ffff:8.8.8.8", false},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			if got := blockedDestination(netip.MustParseAddr(tc.addr)); got != tc.blocked {
				t.Errorf("blockedDestination(%s) = %v, want %v", tc.addr, got, tc.blocked)
			}
		})
	}
}

func TestGuardControlFailsClosed(t *testing.T) {
	control := guardControl(nil)
	for _, address := range []string{"127.0.0.1:443", "[::1]:443", "not-an-address", "127.0.0.1%lo0:443"} {
		if err := control("tcp", address, nil); !errors.Is(err, errPrivateDestination) {
			t.Errorf("guardControl(%q) = %v, want errPrivateDestination", address, err)
		}
	}
	if err := control("tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("a public address was refused: %v", err)
	}
}

func TestGuardControlRefusesTheHostsOwnAddresses(t *testing.T) {
	control := guardControl(map[netip.Addr]bool{netip.MustParseAddr("8.8.4.4"): true})
	for _, address := range []string{"8.8.4.4:443", "[::ffff:8.8.4.4]:443", "[64:ff9b::808:404]:443"} {
		if err := control("tcp", address, nil); !errors.Is(err, errPrivateDestination) {
			t.Errorf("guardControl(%q) = %v, want errPrivateDestination", address, err)
		}
	}
	if err := control("tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("a public address that isn't the host's was refused: %v", err)
	}
}

func TestGuardRefusesToStartWithoutTheMachinesAddresses(t *testing.T) {
	restore := interfaceAddrs
	interfaceAddrs = func() ([]net.Addr, error) { return nil, errors.New("netlink: permission denied") }
	t.Cleanup(func() { interfaceAddrs = restore })

	if _, err := newGuardedUpstreamTransport(); err == nil || !strings.Contains(err.Error(), "--socks5-allow-private-destinations") {
		t.Fatalf("err = %v, want a refusal that names the opt-out flag", err)
	}
}
