package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
)

// Go's monotonic clock pauses while the machine is suspended, but the server
// expires tokens on the wall clock. Timestamps that keep a monotonic reading
// therefore under-count elapsed time after a suspend, which is why
// ManageTokenLifecycle kept renewing an expired token for hours of awake time.
// The lifecycle's clocks must be wall-clock (Round(0)) values.

func renewTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/renew" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.UniversalAuthRefreshResponse{
			AccessToken:       "renewed-token",
			AccessTokenTTL:    1,
			AccessTokenMaxTTL: 60,
		})
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)
	return server
}

func isWallClock(t time.Time) bool {
	return t == t.Round(0)
}

func TestRefreshAccessTokenStoresWallClockTime(t *testing.T) {
	renewTokenServer(t)
	tm := &AgentManager{newAccessTokenNotificationChan: make(chan bool, 1)}

	if err := tm.RefreshAccessToken("old-token"); err != nil {
		t.Fatalf("RefreshAccessToken failed: %v", err)
	}
	if tm.accessTokenRefreshedTime.IsZero() {
		t.Fatal("expected accessTokenRefreshedTime to be set after a successful refresh")
	}
	if !isWallClock(tm.accessTokenRefreshedTime) {
		t.Fatalf("accessTokenRefreshedTime carries a monotonic reading, so machine-suspend time would not count toward the token TTL: %v", tm.accessTokenRefreshedTime)
	}
}

func TestManageTokenLifecycleStoresWallClockTimes(t *testing.T) {
	renewTokenServer(t)

	sinkFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(sinkFile, []byte("stale-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := &AgentManager{
		filePaths:                      []Sink{{Type: "file", Config: SinkDetails{Path: sinkFile}}},
		newAccessTokenNotificationChan: make(chan bool, 16),
	}

	done := make(chan struct{})
	go func() {
		tm.ManageTokenLifecycle()
		close(done)
	}()

	deadline := time.After(10 * time.Second)
	for tm.accessTokenFetchedTime.IsZero() {
		select {
		case <-deadline:
			t.Fatal("ManageTokenLifecycle never fetched and refreshed the sink token")
		case <-time.After(10 * time.Millisecond):
		}
	}
	tm.isShuttingDown = true

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ManageTokenLifecycle did not return after shutdown")
	}

	if !isWallClock(tm.accessTokenFetchedTime) {
		t.Fatalf("accessTokenFetchedTime carries a monotonic reading, so machine-suspend time would not count toward the max TTL: %v", tm.accessTokenFetchedTime)
	}
	if !isWallClock(tm.accessTokenRefreshedTime) {
		t.Fatalf("accessTokenRefreshedTime carries a monotonic reading, so machine-suspend time would not count toward the TTL refresh schedule: %v", tm.accessTokenRefreshedTime)
	}
}

func TestSleepUntilWallClockPastDeadlineReturnsImmediately(t *testing.T) {
	start := time.Now()
	sleepUntilWallClock(time.Now().Add(-time.Hour))
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("sleepUntilWallClock blocked %s on an already-past deadline", elapsed)
	}
}

func TestSleepUntilWallClockSleepsUntilDeadline(t *testing.T) {
	start := time.Now()
	sleepUntilWallClock(time.Now().Round(0).Add(120 * time.Millisecond))
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("sleepUntilWallClock returned after %s, before the deadline", elapsed)
	}
}

// The lifecycle waits in bounded chunks so that a machine suspend, during
// which Go's monotonic timers freeze, cannot keep the goroutine asleep for the
// entire suspend. One chunk is the most a deadline can overshoot after wake.
func TestSleepUntilWallClockChunkIsBounded(t *testing.T) {
	if tokenLifecycleMaxSleep > 30*time.Second {
		t.Fatalf("tokenLifecycleMaxSleep = %s: a single monotonic chunk must stay short enough to notice wake-up quickly", tokenLifecycleMaxSleep)
	}
}
