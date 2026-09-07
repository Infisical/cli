package agentvault

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
)

// A proxy whose heartbeat is met with 401 twice in a row exits; one whose control plane is merely down
// (5xx) keeps polling, because that is the case the grace window exists for.
func newPollLoopFixture(t *testing.T, heartbeatStatus int) (*proxyServer, *store) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(heartbeatStatus)
		_, _ = w.Write([]byte(`{"message":"no"}`))
	}))
	t.Cleanup(srv.Close)
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })

	ps := &proxyServer{
		opts:   Options{ProxyToken: func() string { return "dead" }},
		config: ProxyConfig{PollInterval: 1, UnmatchedHost: UnmatchedAllow},
	}
	ps.cache = newSessionCache(newInfisicalResolver(ps.opts.ProxyToken), ps.pollInterval)
	return ps, newStore(t.TempDir())
}

func TestPollLoopExitsAfterTwoRejectedHeartbeats(t *testing.T) {
	ps, st := newPollLoopFixture(t, http.StatusUnauthorized)
	stop := make(chan struct{})
	fatal := make(chan error, 1)
	go ps.pollLoop(st, stop, fatal)

	select {
	case err := <-fatal:
		if err != errProxyTokenRejected {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("poll loop kept running after two 401 heartbeats")
	}
}

func TestPollLoopKeepsRunningWhileInfisicalIsDown(t *testing.T) {
	ps, st := newPollLoopFixture(t, http.StatusBadGateway)
	stop := make(chan struct{})
	fatal := make(chan error, 1)
	go ps.pollLoop(st, stop, fatal)

	select {
	case err := <-fatal:
		t.Fatalf("poll loop exited on a 502: %v", err)
	case <-time.After(3 * time.Second):
	}
	close(stop)
}
