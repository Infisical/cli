package agentvault

import (
	"errors"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

type stubResolver struct {
	calls  int
	result *resolveResult
	err    error
}

func (s *stubResolver) resolve(string) (*resolveResult, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func connectionWithSecret(secret string) *resolvedConnection {
	return &resolvedConnection{
		id:           "c1",
		name:         "conn",
		hostPatterns: parseHostPatterns("api.foo.com"),
		credential:   credential{kind: credentialBearer, value: []byte(secret)},
	}
}

func newTestCache(resolver sessionResolver) *sessionCache {
	return newSessionCache(resolver, func() time.Duration { return time.Minute })
}

func TestCacheKeyIsTheTokenHashNotTheToken(t *testing.T) {
	token := "agv_super_secret_session_token"
	resolver := &stubResolver{result: &resolveResult{SessionID: "s1", Connections: []*resolvedConnection{connectionWithSecret("v")}}}
	cache := newTestCache(resolver)

	if _, err := cache.get(token); err != nil {
		t.Fatalf("get: %v", err)
	}

	for key := range cache.entries {
		if key == token {
			t.Fatal("the raw session token is being used as a cache key")
		}
	}
	if _, ok := cache.entries[sessionKey(token)]; !ok {
		t.Fatal("the entry should be keyed by the token hash")
	}
}

func TestExpiredSessionIsDroppedWithoutACall(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	resolver := &stubResolver{result: &resolveResult{SessionID: "s1", ExpiresAt: &past}}
	cache := newTestCache(resolver)

	if _, err := cache.get("agv_token"); err != nil {
		t.Fatalf("first get: %v", err)
	}
	callsAfterFirst := resolver.calls

	if _, err := cache.get("agv_token"); !errors.Is(err, errSessionGone) {
		t.Fatalf("expected the session to be gone, got %v", err)
	}
	if resolver.calls != callsAfterFirst {
		t.Fatalf("an expired entry should be dropped without a call; calls went %d -> %d", callsAfterFirst, resolver.calls)
	}
}

func TestRefreshDropsAGoneSessionImmediately(t *testing.T) {
	for _, status := range []int{401, 404} {
		t.Run(map[int]string{401: "revoked or expired", 404: "actor deleted or org mismatch"}[status], func(t *testing.T) {
			resolver := &stubResolver{result: &resolveResult{SessionID: "s1", Connections: []*resolvedConnection{connectionWithSecret("v")}}}
			cache := newTestCache(resolver)
			if _, err := cache.get("agv_token"); err != nil {
				t.Fatalf("get: %v", err)
			}

			resolver.err = &api.APIError{StatusCode: status}
			cache.refresh()

			if len(cache.entries) != 0 {
				t.Fatalf("a %d should drop the session now, %d entries remain", status, len(cache.entries))
			}
		})
	}
}

func TestRefreshKeepsServingWhileInfisicalIsUnreachable(t *testing.T) {
	resolver := &stubResolver{result: &resolveResult{SessionID: "s1", Connections: []*resolvedConnection{connectionWithSecret("v")}}}
	cache := newTestCache(resolver)
	if _, err := cache.get("agv_token"); err != nil {
		t.Fatalf("get: %v", err)
	}

	resolver.err = &api.APIError{StatusCode: 503}
	cache.refresh()
	if len(cache.entries) != 1 {
		t.Fatal("an unreachable Infisical should not drop the session immediately")
	}

	key := sessionKey("agv_token")
	cache.entries[key].fetchedAt = time.Now().Add(-(unreachableGraceIntervals + 1) * time.Minute)
	cache.refresh()
	if len(cache.entries) != 0 {
		t.Fatal("the session should be dropped once the grace window has passed")
	}
}

func TestCacheIsBounded(t *testing.T) {
	resolver := &stubResolver{result: &resolveResult{SessionID: "s1", Connections: []*resolvedConnection{connectionWithSecret("v")}}}
	cache := newTestCache(resolver)

	for i := 0; i < maxSessionCacheEntries+50; i++ {
		cache.entries[sessionKey(string(rune(i))+"pad")] = &sessionEntry{lastSeen: time.Now()}
	}
	cache.mu.Lock()
	cache.evictIfFullLocked()
	cache.mu.Unlock()

	if len(cache.entries) > maxSessionCacheEntries+50 {
		t.Fatal("eviction should not grow the cache")
	}
}

func TestStaleEntryIsNotServedFromTheCache(t *testing.T) {
	resolver := &stubResolver{result: &resolveResult{SessionID: "s1", Connections: []*resolvedConnection{connectionWithSecret("old")}}}
	cache := newTestCache(resolver)

	if _, err := cache.get("agv_tok"); err != nil {
		t.Fatalf("first get: %v", err)
	}

	key := sessionKey("agv_tok")
	cache.mu.Lock()
	cache.entries[key].fetchedAt = time.Now().Add(-cache.grace() - time.Second)
	cache.mu.Unlock()

	resolver.result = &resolveResult{SessionID: "s1", Connections: []*resolvedConnection{connectionWithSecret("fresh")}}
	conns, err := cache.get("agv_tok")
	if err != nil {
		t.Fatalf("stale get: %v", err)
	}
	if resolver.calls != 2 || string(conns[0].credential.value) != "fresh" {
		t.Fatalf("a stale entry must be re-resolved, got %d calls and %q", resolver.calls, conns[0].credential.value)
	}

	cache.mu.Lock()
	cache.entries[key].fetchedAt = time.Now().Add(-cache.grace() - time.Second)
	cache.mu.Unlock()
	resolver.err = errors.New("control plane hung")
	if _, err := cache.get("agv_tok"); err == nil {
		t.Fatal("a stale entry that cannot be re-resolved must not be served")
	}
}

func TestRefreshTreatsEveryDefinitiveRefusalAsTerminal(t *testing.T) {
	for _, tc := range []struct {
		status int
		kept   bool
	}{
		{400, false}, {401, false}, {403, false}, {404, false}, {422, false},
		{408, true}, {429, true}, {500, true}, {502, true},
	} {
		resolver := &stubResolver{result: &resolveResult{SessionID: "s1", Connections: []*resolvedConnection{connectionWithSecret("v")}}}
		cache := newTestCache(resolver)
		if _, err := cache.get("tok"); err != nil {
			t.Fatal(err)
		}
		resolver.err = &api.APIError{StatusCode: tc.status}
		cache.refresh()
		_, kept := cache.get("tok")
		if (kept == nil) != tc.kept {
			t.Fatalf("status %d: credential still served = %v, want %v", tc.status, kept == nil, tc.kept)
		}
	}
}

func TestARejectedProxyTokenDropsTheSessionButIsNotASessionVerdict(t *testing.T) {
	err := &api.APIError{StatusCode: 401, Name: proxyTokenRejectedName, ErrorMessage: "Agent Vault proxy token has been revoked"}
	if isSessionGone(err) {
		t.Fatal("a rejected proxy token was read as the session being gone")
	}
	if !isProxyTokenRejected(err) {
		t.Fatal("the named 401 was not recognised")
	}

	resolver := &stubResolver{result: &resolveResult{SessionID: "s1", Connections: []*resolvedConnection{connectionWithSecret("v")}}}
	cache := newTestCache(resolver)
	if _, e := cache.get("tok"); e != nil {
		t.Fatal(e)
	}
	resolver.err = err
	cache.refresh()
	if _, e := cache.get("tok"); e == nil {
		t.Fatal("the credential kept flowing after the proxy's own token was rejected")
	}
}

func TestAnUnnamed401StillEndsTheSession(t *testing.T) {
	if !isSessionGone(&api.APIError{StatusCode: 401, Name: "UnauthorizedError", ErrorMessage: "Session revoked"}) {
		t.Fatal("a plain 401 from an older server must still end the session")
	}
}
