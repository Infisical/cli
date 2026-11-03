package agentvault

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
)

func TestMissBudgetCapsLookupsAcrossAddresses(t *testing.T) {
	b := newMissBudget(0.001, 3)
	admitted := 0
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"} {
		if b.admit(ip) {
			admitted++
		}
	}
	if admitted != 3 {
		t.Fatalf("admitted %d, want the burst of 3", admitted)
	}
}

func TestMissBudgetSlowsAnAddressWhoseLoginsAllFail(t *testing.T) {
	gone := &api.APIError{StatusCode: 401, Name: infisicalUnauthorizedName}
	b := newMissBudget(1000, 1000)
	for i := 0; i < socks5SuspectRefusals; i++ {
		b.record("192.0.2.1", gone)
	}
	if !b.admit("192.0.2.1") {
		t.Fatal("the first lookup in a second should still go through")
	}
	if b.admit("192.0.2.1") {
		t.Fatal("an address whose logins all failed got a second lookup in the same second")
	}
	if !b.admit("192.0.2.2") || !b.admit("192.0.2.2") {
		t.Fatal("another address was slowed by the first one's failures")
	}

	b.record("192.0.2.1", nil)
	if !b.admit("192.0.2.1") || !b.admit("192.0.2.1") {
		t.Fatal("an address with a recent successful login stayed slowed, though E2B shares addresses")
	}
}

func TestMissBudgetIgnoresFailuresThatSayNothingAboutTheClient(t *testing.T) {
	b := newMissBudget(1000, 1000)
	for i := 0; i < 2*socks5SuspectRefusals; i++ {
		b.record("192.0.2.1", errors.New("dial tcp: connection refused"))
		b.record("192.0.2.1", errResolveBudget)
	}
	if !b.admit("192.0.2.1") || !b.admit("192.0.2.1") {
		t.Fatal("an outage on the proxy's side counted against the client")
	}
}

func TestMissBudgetBoundsTheAddressesItTracks(t *testing.T) {
	gone := &api.APIError{StatusCode: 401, Name: infisicalUnauthorizedName}
	b := newMissBudget(1000, 1000)
	for i := 0; i < socks5MaxTrackedIPs+100; i++ {
		b.record(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), gone)
	}
	b.mu.Lock()
	n := len(b.ips)
	b.mu.Unlock()
	if n > socks5MaxTrackedIPs {
		t.Fatalf("tracking %d addresses, want at most %d", n, socks5MaxTrackedIPs)
	}
}

func TestMissBudgetIsSafeForConcurrentLogins(t *testing.T) {
	gone := &api.APIError{StatusCode: 401, Name: infisicalUnauthorizedName}
	b := newMissBudget(1000, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := []string{"192.0.2.1", "192.0.2.2"}[i%2]
			for j := 0; j < 50; j++ {
				b.admit(ip)
				b.record(ip, gone)
			}
		}(i)
	}
	wg.Wait()
}
