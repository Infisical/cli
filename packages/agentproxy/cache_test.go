package agentproxy

import (
	"fmt"
	"testing"
	"time"
)

// When the cache is full, inserting a new scope must evict the least-recently-seen entry (keeping
// actively-used agents cached) rather than reject the new one or grow the map without bound.
func TestAgentCacheEvictsLeastRecentlySeenWhenFull(t *testing.T) {
	a := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))

	base := time.Now()
	for i := 0; i < maxAgentCacheEntries; i++ {
		// k0 is the most recently seen (active); higher indices are progressively staler, all well
		// within agentInactiveTTL so the inactive-cleanup pass leaves them alone and LRU decides.
		a.entries[fmt.Sprintf("k%d", i)] = &agentEntry{lastSeen: base.Add(-time.Duration(i) * time.Millisecond)}
	}

	active := "k0"
	oldest := fmt.Sprintf("k%d", maxAgentCacheEntries-1)

	a.evictIfFullLocked("new-scope")

	if len(a.entries) >= maxAgentCacheEntries {
		t.Fatalf("expected room for a new entry after eviction, still have %d", len(a.entries))
	}
	if _, ok := a.entries[oldest]; ok {
		t.Fatalf("expected least-recently-seen entry %q to be evicted", oldest)
	}
	if _, ok := a.entries[active]; !ok {
		t.Fatalf("expected active entry %q to survive eviction", active)
	}
}

// A key already present must not trigger eviction — updating an existing scope isn't growth.
func TestAgentCacheNoEvictionWhenReplacing(t *testing.T) {
	a := newAgentCache(func() string { return "" }, newLeaseStore(func() string { return "" }))

	base := time.Now()
	for i := 0; i < maxAgentCacheEntries; i++ {
		a.entries[fmt.Sprintf("k%d", i)] = &agentEntry{lastSeen: base.Add(-time.Duration(i) * time.Millisecond)}
	}

	a.evictIfFullLocked("k5")

	if len(a.entries) != maxAgentCacheEntries {
		t.Fatalf("expected no eviction when replacing an existing key, size changed to %d", len(a.entries))
	}
}
