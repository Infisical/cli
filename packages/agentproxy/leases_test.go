package agentproxy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testScope() agentScope {
	return agentScope{projectID: "proj", environment: "prod", secretPath: "/"}
}

func testKey(name string) leaseKey {
	return leaseKey{jwt: "jwt", scope: testScope(), secretName: name, configHash: ""}
}

// newTestLeaseStore builds a store with an injected minter that returns a deterministic value per mint and
// counts invocations.
func newTestLeaseStore(ttl time.Duration, mintCount *int64) *leaseStore {
	s := &leaseStore{
		entries: make(map[leaseKey]*leaseEntry),
		wake:    make(chan struct{}, 1),
	}
	var seq int64
	s.mint = func(args leaseMintArgs) (leaseMintResult, error) {
		atomic.AddInt64(mintCount, 1)
		n := atomic.AddInt64(&seq, 1)
		return leaseMintResult{
			leaseID:  fmt.Sprintf("lease-%d", n),
			expireAt: time.Now().Add(ttl),
			data:     map[string]interface{}{"TOKEN": fmt.Sprintf("value-%d", n)},
		}, nil
	}
	s.revoke = func(_, _, _, _ string) error { return nil }
	return s
}

func TestCanonicalConfigHash(t *testing.T) {
	if canonicalConfigHash(nil) != "" {
		t.Fatal("nil config should hash to empty string")
	}
	if canonicalConfigHash(map[string]interface{}{}) != "" {
		t.Fatal("empty config should hash to empty string")
	}
	a := canonicalConfigHash(map[string]interface{}{"namespace": "prod", "extra": "x"})
	b := canonicalConfigHash(map[string]interface{}{"extra": "x", "namespace": "prod"})
	if a != b {
		t.Fatal("hash must be independent of key order")
	}
	if canonicalConfigHash(map[string]interface{}{"namespace": "prod"}) == a {
		t.Fatal("different config must hash differently")
	}
}

func TestRegisterDoesNotMint(t *testing.T) {
	var mints int64
	s := newTestLeaseStore(time.Hour, &mints)
	s.register(testKey("db"), leaseSpec{projectSlug: "slug"})
	if atomic.LoadInt64(&mints) != 0 {
		t.Fatalf("register should not mint, got %d mints", mints)
	}
}

func TestValueLazyMintAndReuse(t *testing.T) {
	var mints int64
	s := newTestLeaseStore(time.Hour, &mints)
	key := testKey("db")
	s.register(key, leaseSpec{projectSlug: "slug"})

	v, ok := s.value(key, "TOKEN")
	if !ok || v != "value-1" {
		t.Fatalf("expected value-1, got %q ok=%v", v, ok)
	}
	if _, ok := s.value(key, "TOKEN"); !ok {
		t.Fatal("second read should hit cache")
	}
	if atomic.LoadInt64(&mints) != 1 {
		t.Fatalf("expected exactly 1 mint, got %d", mints)
	}
}

func TestValueConcurrentSingleMint(t *testing.T) {
	var mints int64
	s := newTestLeaseStore(time.Hour, &mints)
	key := testKey("db")
	s.register(key, leaseSpec{projectSlug: "slug"})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.value(key, "TOKEN")
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt64(&mints); got != 1 {
		t.Fatalf("singleflight should collapse concurrent mints to 1, got %d", got)
	}
}

func TestValueMintFailureFailsOpen(t *testing.T) {
	s := &leaseStore{entries: make(map[leaseKey]*leaseEntry), wake: make(chan struct{}, 1)}
	s.mint = func(args leaseMintArgs) (leaseMintResult, error) { return leaseMintResult{}, fmt.Errorf("boom") }
	s.revoke = func(_, _, _, _ string) error { return nil }
	key := testKey("db")
	s.register(key, leaseSpec{})
	if v, ok := s.value(key, "TOKEN"); ok || v != "" {
		t.Fatalf("mint failure should return ok=false, got %q ok=%v", v, ok)
	}
}

func TestValueMissingField(t *testing.T) {
	var mints int64
	s := newTestLeaseStore(time.Hour, &mints)
	key := testKey("db")
	s.register(key, leaseSpec{})
	if _, ok := s.value(key, "NONEXISTENT"); ok {
		t.Fatal("missing field should return ok=false")
	}
}

func TestRefreshPassReMintsNearExpiry(t *testing.T) {
	var mints int64
	// long TTL so a re-minted lease is served from cache (not re-minted again by the skew guard)
	s := newTestLeaseStore(time.Hour, &mints)
	var revokes int64
	s.revoke = func(_, _, _, _ string) error { atomic.AddInt64(&revokes, 1); return nil }
	key := testKey("db")
	s.register(key, leaseSpec{})

	// initial lazy mint
	if _, ok := s.value(key, "TOKEN"); !ok {
		t.Fatal("initial mint failed")
	}
	// force the lease within its refresh buffer so refreshPass re-mints it
	s.mu.Lock()
	s.entries[key].expireAt = time.Now().Add(100 * time.Millisecond)
	s.mu.Unlock()
	live := map[string]struct{}{cacheKey(key.jwt, key.scope): {}}

	s.refreshPass(live)

	if atomic.LoadInt64(&mints) < 2 {
		t.Fatalf("expected a re-mint, got %d mints", mints)
	}
	if atomic.LoadInt64(&revokes) != 0 {
		t.Fatal("re-mint must never proactively revoke the old lease")
	}
	// the fresh lease value is now what gets served
	if v, ok := s.value(key, "TOKEN"); !ok || v != "value-2" {
		t.Fatalf("expected the re-minted value-2 to be served, got %q ok=%v", v, ok)
	}
}

func TestRefreshPassSkipsNonLiveSessions(t *testing.T) {
	var mints int64
	s := newTestLeaseStore(2*time.Second, &mints)
	key := testKey("db")
	s.register(key, leaseSpec{})
	s.value(key, "TOKEN")
	before := atomic.LoadInt64(&mints)

	// empty live set: the session is gone, so no re-mint
	s.refreshPass(map[string]struct{}{})
	if atomic.LoadInt64(&mints) != before {
		t.Fatal("leases for non-live sessions must not be re-minted")
	}
}

func TestRefreshBufferProportionalToTTL(t *testing.T) {
	if refreshBuffer(30*time.Second) != 6*time.Second {
		t.Fatalf("expected ttl/5 for short ttl, got %v", refreshBuffer(30*time.Second))
	}
	if refreshBuffer(time.Hour) != time.Minute {
		t.Fatalf("expected 60s cap for long ttl, got %v", refreshBuffer(time.Hour))
	}
}

func TestFailedFirstMintDoesNotScheduleProactiveWork(t *testing.T) {
	// a never-minted entry whose first mint failed must not produce a scheduling deadline (else the
	// refresh loop would busy-spin at the 1s floor until the session goes inactive)
	s := &leaseStore{entries: make(map[leaseKey]*leaseEntry), wake: make(chan struct{}, 1)}
	s.mint = func(args leaseMintArgs) (leaseMintResult, error) { return leaseMintResult{}, fmt.Errorf("boom") }
	s.revoke = func(_, _, _, _ string) error { return nil }
	key := testKey("db")
	s.register(key, leaseSpec{})
	s.value(key, "TOKEN") // fails, sets nextMintAttempt but leaseID stays ""

	live := map[string]struct{}{cacheKey(key.jwt, key.scope): {}}
	if next := s.nextDeadline(live); !next.IsZero() {
		t.Fatalf("never-minted failed entry must not schedule proactive work, got %v", next)
	}
}

func TestValueRespectsMintBackoff(t *testing.T) {
	var attempts int64
	s := &leaseStore{entries: make(map[leaseKey]*leaseEntry), wake: make(chan struct{}, 1)}
	s.mint = func(args leaseMintArgs) (leaseMintResult, error) {
		atomic.AddInt64(&attempts, 1)
		return leaseMintResult{}, fmt.Errorf("boom")
	}
	s.revoke = func(_, _, _, _ string) error { return nil }
	key := testKey("db")
	s.register(key, leaseSpec{})

	s.value(key, "TOKEN") // first attempt fails, arms backoff
	s.value(key, "TOKEN") // within backoff: must not attempt again
	if got := atomic.LoadInt64(&attempts); got != 1 {
		t.Fatalf("second request within backoff should not re-attempt mint, got %d attempts", got)
	}
}

// Two credentials referencing the same dynamic secret (e.g. basic-auth username + password) must draw
// from ONE minted lease, so the values actually belong together. Different fields, same key => 1 mint.
func TestSameSecretMultipleFieldsShareOneLease(t *testing.T) {
	var mints int64
	s := &leaseStore{entries: make(map[leaseKey]*leaseEntry), wake: make(chan struct{}, 1)}
	s.mint = func(args leaseMintArgs) (leaseMintResult, error) {
		atomic.AddInt64(&mints, 1)
		return leaseMintResult{
			leaseID:  "lease-1",
			expireAt: time.Now().Add(time.Hour),
			data:     map[string]interface{}{"DB_USERNAME": "u1", "DB_PASSWORD": "p1"},
		}, nil
	}
	s.revoke = func(_, _, _, _ string) error { return nil }

	key := testKey("pg")
	// both credentials build the same key (same secret + config), so both register the same entry
	s.register(key, leaseSpec{})
	s.register(key, leaseSpec{})

	user, okU := s.value(key, "DB_USERNAME")
	pass, okP := s.value(key, "DB_PASSWORD")
	if !okU || !okP || user != "u1" || pass != "p1" {
		t.Fatalf("expected u1/p1 from one lease, got %q/%q (ok %v/%v)", user, pass, okU, okP)
	}
	if got := atomic.LoadInt64(&mints); got != 1 {
		t.Fatalf("same secret referenced twice must mint exactly one lease, got %d", got)
	}
}

func TestRevokeAllRevokesLiveLeases(t *testing.T) {
	var mints int64
	s := newTestLeaseStore(time.Hour, &mints)
	var revoked int64
	s.revoke = func(_, _, _, _ string) error { atomic.AddInt64(&revoked, 1); return nil }
	for i := 0; i < 3; i++ {
		key := testKey(fmt.Sprintf("db-%d", i))
		s.register(key, leaseSpec{})
		s.value(key, "TOKEN")
	}
	s.revokeAll(context.Background())
	if atomic.LoadInt64(&revoked) != 3 {
		t.Fatalf("expected 3 revokes, got %d", revoked)
	}
}
