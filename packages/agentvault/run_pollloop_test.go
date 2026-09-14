package agentvault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

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
		config: ProxyConfig{PollInterval: 1, TrafficPolicy: TrafficPolicyAnyHost},
	}
	resolver, err := newInfisicalResolver(ps.opts.ProxyToken)
	if err != nil {
		t.Fatal(err)
	}
	ps.cache = newSessionCache(resolver, ps.pollInterval)
	return ps, newStore(t.TempDir())
}

func TestPollLoopExitsAfterTwoRejectedHeartbeats(t *testing.T) {
	ps, st := newPollLoopFixture(t, http.StatusUnauthorized)
	stop := make(chan struct{})
	fatal := make(chan error, 1)
	done := runPollLoop(ps, st, stop, fatal)

	select {
	case err := <-fatal:
		if err != errProxyTokenRejected {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("poll loop kept running after two 401 heartbeats")
	}
	<-done
}

// The fixture's Cleanup puts the URL global back; the loop has to have stopped reading it first.
func runPollLoop(ps *proxyServer, st *store, stop <-chan struct{}, fatal chan<- error) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ps.pollLoop(st, stop, fatal)
	}()
	return done
}

func TestPollLoopKeepsRunningWhileInfisicalIsDown(t *testing.T) {
	ps, st := newPollLoopFixture(t, http.StatusBadGateway)
	stop := make(chan struct{})
	fatal := make(chan error, 1)
	done := runPollLoop(ps, st, stop, fatal)

	select {
	case err := <-fatal:
		t.Fatalf("poll loop exited on a 502: %v", err)
	case <-time.After(3 * time.Second):
	}
	close(stop)
	<-done
}

// A settings change is written from the state the process holds. Re-reading the file first, as tick once
// did, found nothing when the file was missing at that instant and wrote it back without the token.
func TestTickPersistsSettingsFromMemoryWhenTheFileIsGone(t *testing.T) {
	body, err := json.Marshal(api.AgentVaultHeartbeatResponse{
		Config: api.AgentVaultProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, PollInterval: 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })

	st := newStore(t.TempDir())
	loaded := persistedState{ProxyID: "p1", AccessToken: "tok", Config: ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost, PollInterval: 60}}
	if err := st.saveState(loaded); err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{
		opts:      Options{ProxyToken: func() string { return "tok" }},
		config:    loaded.Config,
		persisted: loaded,
	}
	resolver, err := newInfisicalResolver(ps.opts.ProxyToken)
	if err != nil {
		t.Fatal(err)
	}
	ps.cache = newSessionCache(resolver, ps.pollInterval)

	if err := os.Remove(filepath.Join(st.dir, proxyStateFile)); err != nil {
		t.Fatal(err)
	}
	ps.tick(st)

	back, found, err := st.loadState()
	if err != nil || !found {
		t.Fatalf("state not written back: found=%v err=%v", found, err)
	}
	if back.AccessToken != "tok" || back.ProxyID != "p1" {
		t.Fatalf("the token or proxy id was lost: %+v", back)
	}
	if back.Config.TrafficPolicy != TrafficPolicyBundleHosts || back.Config.PollInterval != 30 {
		t.Fatalf("the new settings were not persisted: %+v", back.Config)
	}
}

func TestTickKeepsTheCurrentSettingsWhenTheHeartbeatCarriesNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })

	st := newStore(t.TempDir())
	loaded := persistedState{ProxyID: "p1", AccessToken: "tok", Config: ProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, PollInterval: 10}}
	if err := st.saveState(loaded); err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{opts: Options{ProxyToken: func() string { return "tok" }}, config: loaded.Config, persisted: loaded}
	resolver, err := newInfisicalResolver(ps.opts.ProxyToken)
	if err != nil {
		t.Fatal(err)
	}
	ps.cache = newSessionCache(resolver, ps.pollInterval)

	ps.tick(st)

	if got := ps.currentConfig(); got != loaded.Config {
		t.Fatalf("a heartbeat with no settings changed the config to %+v", got)
	}
	back, _, _ := st.loadState()
	if back.Config != loaded.Config {
		t.Fatalf("a heartbeat with no settings was persisted: %+v", back.Config)
	}
}
