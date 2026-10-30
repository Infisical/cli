package agentvault

import (
	"errors"
	"net/netip"
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
	for _, address := range []string{"127.0.0.1:443", "[::1]:443", "not-an-address", "127.0.0.1%lo0:443"} {
		if err := guardControl("tcp", address, nil); !errors.Is(err, errPrivateDestination) {
			t.Errorf("guardControl(%q) = %v, want errPrivateDestination", address, err)
		}
	}
	if err := guardControl("tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("a public address was refused: %v", err)
	}
}
