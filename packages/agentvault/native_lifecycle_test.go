package agentvault

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

const nativeTestToken = "agv_native"

func nativeService(id, host string) *resolvedService {
	return &resolvedService{
		id:         id,
		name:       "db-" + id,
		kind:       serviceKindPostgres,
		native:     &nativeTarget{host: host, port: 5432, database: "app", tlsEnabled: true, tlsVerify: true},
		credential: credential{kind: credentialBasic, username: "agent", password: []byte("p")},
	}
}

// A cache holding one session with service db, and one connection open to it.
func openNativeConn(t *testing.T, resolver *stubResolver) (*sessionCache, *nativeConn) {
	t.Helper()
	resolver.result = &resolveResult{SessionID: "s1", Services: []*resolvedService{nativeService("db", "db.internal")}}
	cache := newTestCache(resolver)
	services, err := cache.get(nativeTestToken)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	conn, err := cache.registerNative(nativeTestToken, services[0])
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { cache.releaseNative(conn) })
	return cache, conn
}

func closed(conn *nativeConn) bool { return conn.ctx.Err() != nil }

func polled(cache *sessionCache) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.tokens[sessionKey(nativeTestToken)] != ""
}

func setResult(resolver *stubResolver, result *resolveResult, err error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.result, resolver.err = result, err
}

func TestANativeConnectionClosesWhenItsServiceIsRemoved(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)

	setResult(resolver, &resolveResult{SessionID: "s1", Services: []*resolvedService{}}, nil)
	cache.refreshOne(sessionKey(nativeTestToken), nativeTestToken)

	if !closed(conn) {
		t.Fatal("a connection to a removed service stayed open")
	}
}

func TestANativeConnectionClosesWhenItsServicePointsElsewhere(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)

	setResult(resolver, &resolveResult{SessionID: "s1", Services: []*resolvedService{nativeService("db", "other.internal")}}, nil)
	cache.refreshOne(sessionKey(nativeTestToken), nativeTestToken)

	if !closed(conn) {
		t.Fatal("a connection to a server the service no longer names stayed open")
	}
}

func TestANativeConnectionStaysOpenWhenOnlyItsPasswordChanges(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)

	rotated := nativeService("db", "db.internal")
	rotated.credential.password = []byte("rotated")
	rotated.personalValuesMissing = true
	setResult(resolver, &resolveResult{SessionID: "s1", Services: []*resolvedService{rotated}}, nil)
	cache.refreshOne(sessionKey(nativeTestToken), nativeTestToken)

	if closed(conn) {
		t.Fatal("a password rotation closed a connection whose login was already made")
	}
}

func TestANativeConnectionClosesWhenTheSessionEnds(t *testing.T) {
	gone := &api.APIError{StatusCode: 401, Name: infisicalUnauthorizedName}
	tokenRejected := &api.APIError{StatusCode: 401, Name: proxyTokenRejectedName}
	for name, err := range map[string]error{"session gone": gone, "proxy token rejected": tokenRejected} {
		t.Run(name, func(t *testing.T) {
			resolver := &stubResolver{}
			cache, conn := openNativeConn(t, resolver)

			setResult(resolver, nil, err)
			cache.refreshOne(sessionKey(nativeTestToken), nativeTestToken)

			if !closed(conn) {
				t.Fatal("the connection stayed open after the session ended")
			}
			if polled(cache) {
				t.Fatal("an ended session is still polled")
			}
		})
	}
}

func TestANativeConnectionClosesWhenTheSessionExpires(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)

	past := time.Now().Add(-time.Second)
	cache.mu.Lock()
	cache.entries[sessionKey(nativeTestToken)].expiresAt = &past
	cache.mu.Unlock()
	cache.refresh()

	if !closed(conn) {
		t.Fatal("the connection stayed open past the session's expiry")
	}
}

func TestAnIdleNativeConnectionKeepsItsSessionPolled(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)

	cache.mu.Lock()
	cache.entries[sessionKey(nativeTestToken)].lastSeen = time.Now().Add(-2 * sessionInactiveTTL)
	cache.mu.Unlock()
	before := resolver.callCount()
	cache.refresh()

	if closed(conn) {
		t.Fatal("the idle drop closed a connection")
	}
	if resolver.callCount() != before+1 {
		t.Fatal("a session with an open connection wasn't polled once it went idle")
	}
}

// An outage past the grace window drops the entry, but the session must still be asked about, or a revoke made once
// Infisical is back would never reach the open connection.
func TestAnOutageKeepsANativeSessionPolledAndARevokeAfterItStillCloses(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)
	key := sessionKey(nativeTestToken)

	cache.mu.Lock()
	cache.entries[key].fetchedAt = time.Now().Add(-2 * cache.grace())
	cache.mu.Unlock()
	cache.handleRefreshFailure(key, errors.New("connection refused"))

	cache.mu.Lock()
	_, stillCached := cache.entries[key]
	cache.mu.Unlock()
	if stillCached || closed(conn) || !polled(cache) {
		t.Fatalf("after an outage: cached=%v closed=%v polled=%v, want false false true", stillCached, closed(conn), polled(cache))
	}

	setResult(resolver, nil, &api.APIError{StatusCode: 401, Name: infisicalUnauthorizedName})
	cache.refresh()
	if !closed(conn) {
		t.Fatal("a revoke after the outage didn't close the connection")
	}
}

func TestARefreshAfterAnOutagePutsTheEntryBackAndChecksTheConnection(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)
	key := sessionKey(nativeTestToken)

	cache.mu.Lock()
	cache.forgetLocked(key, false)
	cache.mu.Unlock()
	setResult(resolver, &resolveResult{SessionID: "s1", Services: []*resolvedService{}}, nil)
	cache.refresh()

	if !closed(conn) {
		t.Fatal("a service removed during an outage left its connection open")
	}
}

// The request path re-resolves a session past its grace window, after its entry is gone, so the check is against
// the open connections rather than the entry it replaced.
func TestTheRequestPathReResolveClosesARemovedServicesConnection(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)

	cache.mu.Lock()
	cache.entries[sessionKey(nativeTestToken)].fetchedAt = time.Now().Add(-2 * cache.grace())
	cache.mu.Unlock()
	setResult(resolver, &resolveResult{SessionID: "s1", Services: []*resolvedService{}}, nil)
	if _, err := cache.get(nativeTestToken); err != nil {
		t.Fatalf("get: %v", err)
	}

	if !closed(conn) {
		t.Fatal("the request path's re-resolve left a removed service's connection open")
	}
}

func TestAConnectionIsNotRegisteredForAServiceThatChangedAfterTheLookup(t *testing.T) {
	resolver := &stubResolver{}
	resolver.result = &resolveResult{SessionID: "s1", Services: []*resolvedService{nativeService("db", "db.internal")}}
	cache := newTestCache(resolver)
	services, _ := cache.get(nativeTestToken)
	looked := services[0]

	setResult(resolver, &resolveResult{SessionID: "s1", Services: []*resolvedService{nativeService("db", "other.internal")}}, nil)
	cache.refreshOne(sessionKey(nativeTestToken), nativeTestToken)

	if _, err := cache.registerNative(nativeTestToken, looked); !errors.Is(err, errNativeServiceChanged) {
		t.Fatalf("register after a change: %v, want errNativeServiceChanged", err)
	}
}

func TestAConnectionIsNotRegisteredForASessionThatEndedAfterTheLookup(t *testing.T) {
	resolver := &stubResolver{}
	resolver.result = &resolveResult{SessionID: "s1", Services: []*resolvedService{nativeService("db", "db.internal")}}
	cache := newTestCache(resolver)
	services, _ := cache.get(nativeTestToken)

	setResult(resolver, nil, &api.APIError{StatusCode: 401, Name: infisicalUnauthorizedName})
	cache.refreshOne(sessionKey(nativeTestToken), nativeTestToken)

	if _, err := cache.registerNative(nativeTestToken, services[0]); !errors.Is(err, errSessionGone) {
		t.Fatalf("register after the session ended: %v, want errSessionGone", err)
	}
}

func TestReleasingTheLastConnectionUnpinsTheSession(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)
	key := sessionKey(nativeTestToken)

	cache.mu.Lock()
	cache.forgetLocked(key, false)
	cache.mu.Unlock()
	cache.releaseNative(conn)

	if polled(cache) {
		t.Fatal("a session with no connection and no entry is still polled")
	}
}

func TestShutdownClosesNativeConnectionsAndWaitsForThem(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)
	go func() {
		<-conn.ctx.Done()
		cache.releaseNative(conn)
	}()

	start := time.Now()
	cache.closeNative(time.Second)
	if !closed(conn) || time.Since(start) >= time.Second {
		t.Fatal("shutdown didn't close the connection and wait for it to finish")
	}
}

// The entry goes past the grace window while Infisical is down and is dropped, so only the connection still knows
// when the session ends. It must close then, not when Infisical is back to say so.
func TestANativeConnectionClosesAtExpiryWhileInfisicalIsDown(t *testing.T) {
	resolver := &stubResolver{}
	expiresAt := time.Now().Add(time.Hour)
	resolver.result = &resolveResult{SessionID: "s1", ExpiresAt: &expiresAt, Services: []*resolvedService{nativeService("db", "db.internal")}}
	cache := newTestCache(resolver)
	services, err := cache.get(nativeTestToken)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	conn, err := cache.registerNative(nativeTestToken, services[0])
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { cache.releaseNative(conn) })
	key := sessionKey(nativeTestToken)

	setResult(resolver, nil, errors.New("connection refused"))
	cache.mu.Lock()
	cache.entries[key].fetchedAt = time.Now().Add(-2 * cache.grace())
	cache.mu.Unlock()
	cache.refresh()

	cache.mu.Lock()
	_, stillCached := cache.entries[key]
	cache.mu.Unlock()
	if stillCached || closed(conn) {
		t.Fatalf("after the grace window: cached=%v closed=%v, want false false", stillCached, closed(conn))
	}

	past := time.Now().Add(-time.Second)
	cache.mu.Lock()
	conn.expiresAt = &past
	cache.mu.Unlock()
	cache.refresh()

	if !closed(conn) {
		t.Fatal("the connection stayed open past the session's expiry while Infisical was down")
	}
	if polled(cache) {
		t.Fatal("an expired session is still polled")
	}
}

func TestARefreshMovesAConnectionsExpiryWithTheSession(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)

	later := time.Now().Add(2 * time.Hour)
	setResult(resolver, &resolveResult{SessionID: "s1", ExpiresAt: &later, Services: []*resolvedService{nativeService("db", "db.internal")}}, nil)
	cache.refreshOne(sessionKey(nativeTestToken), nativeTestToken)

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if conn.expiresAt == nil || !conn.expiresAt.Equal(later) {
		t.Fatalf("connection expiry = %v, want the refreshed %v", conn.expiresAt, later)
	}
}

func TestNoConnectionIsRegisteredOnceShutdownBegan(t *testing.T) {
	resolver := &stubResolver{}
	resolver.result = &resolveResult{SessionID: "s1", Services: []*resolvedService{nativeService("db", "db.internal")}}
	cache := newTestCache(resolver)
	services, err := cache.get(nativeTestToken)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	cache.closeNative(time.Second)

	if conn, err := cache.registerNative(nativeTestToken, services[0]); !errors.Is(err, errProxyShuttingDown) {
		if conn != nil {
			cache.releaseNative(conn)
		}
		t.Fatalf("register during shutdown: %v, want errProxyShuttingDown", err)
	}
}

func TestEvictionSkipsASessionWithAnOpenConnection(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)
	pinned := sessionKey(nativeTestToken)

	cache.mu.Lock()
	cache.entries[pinned].lastSeen = time.Now().Add(-(sessionInactiveTTL + time.Minute))
	for i := len(cache.entries); i < maxSessionCacheEntries; i++ {
		cache.entries[sessionKey(fmt.Sprintf("k%d", i))] = &sessionEntry{lastSeen: time.Now()}
	}
	cache.evictIfFullLocked()
	_, kept := cache.entries[pinned]
	size := len(cache.entries)
	cache.mu.Unlock()

	if !kept || closed(conn) {
		t.Fatalf("eviction: pinned kept=%v closed=%v, want true false", kept, closed(conn))
	}
	if size != maxSessionCacheEntries-1 {
		t.Fatalf("cache holds %d entries after eviction, want %d", size, maxSessionCacheEntries-1)
	}
}

// Answers every resolve with result, and while gated holds each one until release is closed.
type gatedResolver struct {
	result  *resolveResult
	gated   atomic.Bool
	started chan struct{}
	release chan struct{}
}

func (g *gatedResolver) resolve(string, *sessionLogGrant) (*resolveResult, error) {
	if g.gated.Load() {
		g.started <- struct{}{}
		<-g.release
	}
	return g.result, nil
}

// A poll that was already out when the session ended must not rebuild its entry from the answer it brings back.
func TestAPollThatLandsAfterTheSessionEndedDoesNotBringItBack(t *testing.T) {
	resolver := &gatedResolver{
		result:  &resolveResult{SessionID: "s1", Services: []*resolvedService{nativeService("db", "db.internal")}},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	cache := newTestCache(resolver)
	services, err := cache.get(nativeTestToken)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	conn, err := cache.registerNative(nativeTestToken, services[0])
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { cache.releaseNative(conn) })
	key := sessionKey(nativeTestToken)

	resolver.gated.Store(true)
	done := make(chan struct{})
	go func() {
		cache.refreshOne(key, nativeTestToken)
		close(done)
	}()
	<-resolver.started
	cache.mu.Lock()
	cache.forgetLocked(key, true)
	cache.mu.Unlock()
	close(resolver.release)
	<-done
	resolver.gated.Store(false)

	cache.mu.Lock()
	_, back := cache.entries[key]
	cache.mu.Unlock()
	if back {
		t.Fatal("the poll's answer brought back a session that ended while it was out")
	}
	if again, err := cache.registerNative(nativeTestToken, services[0]); !errors.Is(err, errSessionGone) {
		if again != nil {
			cache.releaseNative(again)
		}
		t.Fatalf("register after the session ended: %v, want errSessionGone", err)
	}
}

func TestANativeConnectionClosesAtExpiryWithoutAPoll(t *testing.T) {
	resolver := &stubResolver{}
	expiresAt := time.Now().Add(50 * time.Millisecond)
	resolver.result = &resolveResult{SessionID: "s1", ExpiresAt: &expiresAt, Services: []*resolvedService{nativeService("db", "db.internal")}}
	cache := newTestCache(resolver)
	services, err := cache.get(nativeTestToken)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	conn, err := cache.registerNative(nativeTestToken, services[0])
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { cache.releaseNative(conn) })

	select {
	case <-conn.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the connection stayed open past the session's expiry with nothing polling")
	}
}

func TestAnExpiryMovedLaterKeepsTheConnectionOpen(t *testing.T) {
	resolver := &stubResolver{}
	soon := time.Now().Add(100 * time.Millisecond)
	resolver.result = &resolveResult{SessionID: "s1", ExpiresAt: &soon, Services: []*resolvedService{nativeService("db", "db.internal")}}
	cache := newTestCache(resolver)
	services, _ := cache.get(nativeTestToken)
	conn, err := cache.registerNative(nativeTestToken, services[0])
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { cache.releaseNative(conn) })

	later := time.Now().Add(time.Hour)
	setResult(resolver, &resolveResult{SessionID: "s1", ExpiresAt: &later, Services: []*resolvedService{nativeService("db", "db.internal")}}, nil)
	cache.refreshOne(sessionKey(nativeTestToken), nativeTestToken)

	time.Sleep(300 * time.Millisecond)
	if closed(conn) {
		t.Fatal("the connection closed at the old expiry after a refresh moved it later")
	}
}

// Polls that keep failing say nothing about the session, but past the grace window it is no longer served, as an
// HTTP request isn't.
func TestANativeConnectionClosesOnceInfisicalIsUnreachablePastTheGraceWindow(t *testing.T) {
	resolver := &stubResolver{}
	cache, conn := openNativeConn(t, resolver)
	key := sessionKey(nativeTestToken)
	setResult(resolver, nil, errors.New("connection refused"))

	cache.refresh()
	if closed(conn) {
		t.Fatal("a failed poll inside the grace window closed the connection")
	}

	lastAnswer := time.Now().Add(-2 * cache.grace())
	cache.mu.Lock()
	cache.entries[key].fetchedAt = lastAnswer
	conn.fetchedAt = lastAnswer
	cache.mu.Unlock()
	cache.refresh()
	cache.refresh()

	if !closed(conn) {
		t.Fatal("the connection stayed open past the grace window with Infisical unreachable")
	}
}

func TestASessionIsCappedAtItsOpenNativeConnections(t *testing.T) {
	restore := maxNativeConnsPerSession
	maxNativeConnsPerSession = 2
	t.Cleanup(func() { maxNativeConnsPerSession = restore })

	resolver := &stubResolver{}
	resolver.result = &resolveResult{SessionID: "s1", Services: []*resolvedService{nativeService("db", "db.internal")}}
	cache := newTestCache(resolver)
	services, _ := cache.get(nativeTestToken)
	for i := 0; i < 2; i++ {
		conn, err := cache.registerNative(nativeTestToken, services[0])
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		t.Cleanup(func() { cache.releaseNative(conn) })
	}

	conn, err := cache.registerNative(nativeTestToken, services[0])
	if conn != nil {
		cache.releaseNative(conn)
	}
	if err == nil || err.Error() != "this session already has 2 open database or SSH connections. Close some and try again" {
		t.Fatalf("third register: %v, want the per-session limit", err)
	}
}

func TestShutdownWaitsForAnSSHChannelsLastLinesOnlyWhenSSHWasOpen(t *testing.T) {
	old := nativeSSHLateLineWait
	nativeSSHLateLineWait = 200 * time.Millisecond
	t.Cleanup(func() { nativeSSHLateLineWait = old })

	for _, kind := range []string{serviceKindPostgres, serviceKindSSH} {
		resolver := &stubResolver{}
		svc := nativeService("db", "db.internal")
		svc.kind = kind
		resolver.result = &resolveResult{SessionID: "s1", Services: []*resolvedService{svc}}
		cache := newTestCache(resolver)
		services, err := cache.get(nativeTestToken)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := cache.registerNative(nativeTestToken, services[0])
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			<-conn.ctx.Done()
			cache.releaseNative(conn)
		}()

		start := time.Now()
		cache.closeNative(time.Second)
		waited := time.Since(start)
		if kind == serviceKindSSH && waited < nativeSSHLateLineWait {
			t.Errorf("shutdown with an SSH connection returned after %v, want at least %v for its last lines", waited, nativeSSHLateLineWait)
		}
		if kind != serviceKindSSH && waited >= nativeSSHLateLineWait {
			t.Errorf("shutdown with only a %s connection waited %v", kind, waited)
		}
	}
}
