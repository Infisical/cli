package webapp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

func TestDestinationRules(t *testing.T) {
	for _, test := range []struct{ host, want string }{{"APP.Example.", "app.example"}, {"bücher.example", "xn--bcher-kva.example"}, {"::ffff:10.2.3.4", "10.2.3.4"}} {
		got, err := normalizeHost(test.host)
		if err != nil || got != test.want {
			t.Fatalf("normalize %s: %s %v", test.host, got, err)
		}
	}
	for _, test := range []struct {
		host string
		want bool
	}{{"one.example", true}, {"example", false}, {"two.one.example", false}, {"one.example.evil", false}} {
		if hostMatches("*.example", test.host) != test.want {
			t.Fatalf("wildcard %s", test.host)
		}
	}
	policy, err := newDestinationPolicy(ConnectorPolicy{AllowedDestinations: []api.PAMWebDestination{{Host: "app.example", Port: 443, Scheme: "https"}, {Host: "*.example", Port: 80, Scheme: "http"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, cidr := range mandatoryDeny {
		prefix := netip.MustParsePrefix(cidr)
		if !policy.denied(prefix.Addr()) {
			t.Errorf("mandatory range not denied: %s", cidr)
		}
	}
	if !policy.denied(netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Fatal("mapped loopback allowed")
	}
	policy.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.2.3.4")}}, nil
	}
	if _, err := policy.resolve(t.Context(), "app.example.", 443, "https"); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.resolve(t.Context(), "app.example", 443, "http"); err == nil {
		t.Fatal("wrong scheme allowed")
	}
	if _, err := policy.resolve(t.Context(), "one.example", 80, "http"); err == nil {
		t.Fatal("wildcard private destination allowed")
	}
	policy.refresh([]string{"10.2.3.4"})
	if _, err := policy.resolve(t.Context(), "app.example", 443, "https"); err == nil {
		t.Fatal("host address allowed")
	}
	policy.refresh(nil)
	if _, err := policy.resolve(t.Context(), "app.example", 443, "https"); err != nil {
		t.Fatal("host refresh did not update")
	}
	policy.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::ffff:169.254.169.254")}}, nil
	}
	if _, err := policy.resolve(t.Context(), "app.example", 443, "https"); err == nil {
		t.Fatal("rebinding to metadata allowed")
	}
}

func TestConnectorCutClosesEstablishedTunnel(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := &connector{connections: map[net.Conn]bool{}}
	if !c.track(a) {
		t.Fatal("connection not tracked")
	}
	c.cut()
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("established connection survived cutoff")
	}
	x, y := net.Pipe()
	defer y.Close()
	if c.track(x) {
		t.Fatal("connection admitted after shutdown")
	}
}

func TestLeaseHardExpiryAndRenewal(t *testing.T) {
	clock := newLeaseClock(time.Now().Add(80*time.Millisecond), time.Now().Add(time.Hour), 5*time.Second)
	defer clock.Stop()
	select {
	case <-clock.done:
	case <-time.After(time.Second):
		t.Fatal("hard expiry not enforced")
	}
	clock2 := newLeaseClock(time.Now().Add(time.Second), time.Now().Add(50*time.Millisecond), 0)
	defer clock2.Stop()
	clock2.Renew(time.Now().Add(200 * time.Millisecond))
	select {
	case <-clock2.done:
		t.Fatal("renewal ignored")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-clock2.done:
	case <-time.After(time.Second):
		t.Fatal("renewed lease did not expire")
	}
}
