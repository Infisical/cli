package agentvault

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

func shortBootstrapRetries(t *testing.T) {
	t.Helper()
	prevWindow, prevBackoff := bootstrapRetryWindow, bootstrapFirstBackoff
	bootstrapRetryWindow, bootstrapFirstBackoff = 500*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { bootstrapRetryWindow, bootstrapFirstBackoff = prevWindow, prevBackoff })
}

// Each call gets the attempt number, counted from 1, and the decoded request.
func fakeBootstrap(t *testing.T, respond func(w http.ResponseWriter, attempt int32, req api.AgentVaultProxyBootstrapRequest)) *atomic.Int32 {
	t.Helper()
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent-vault/proxy/bootstrap" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer pxt" {
			t.Errorf("the proxy token was not sent as the bearer: %q", got)
		}
		var req api.AgentVaultProxyBootstrapRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		respond(w, attempts.Add(1), req)
	}))
	t.Cleanup(srv.Close)
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })
	return &attempts
}

func bootstrapResponse(rootCa *api.AgentVaultProxyRootCa) api.AgentVaultProxyBootstrapResponse {
	return api.AgentVaultProxyBootstrapResponse{
		ProxyID: "p1",
		Name:    "payments",
		Config:  api.AgentVaultProxyConfig{TrafficPolicy: TrafficPolicyBundleHosts, AllowedHosts: "a.example.com", PollInterval: 30},
		RootCa:  rootCa,
	}
}

func TestProxyTokenServesTheCaInfisicalReturns(t *testing.T) {
	certPEM, _, pkcs8 := caPairPEM(t)
	fakeBootstrap(t, func(w http.ResponseWriter, _ int32, req api.AgentVaultProxyBootstrapRequest) {
		if req.ServedCaCertificate != "" {
			t.Errorf("no CA was passed, yet bootstrap reported one")
		}
		_ = json.NewEncoder(w).Encode(bootstrapResponse(&api.AgentVaultProxyRootCa{Certificate: certPEM, PrivateKey: pkcs8}))
	})

	state, ca, err := loadFromProxyToken("pxt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca.RootPEM()) != certPEM {
		t.Fatal("the proxy serves a CA other than the one Infisical returned")
	}
	if state.ProxyID != "p1" || state.ProxyName != "payments" || state.AccessToken != "pxt" {
		t.Fatalf("the proxy's identity did not come from bootstrap: %+v", state)
	}
	if state.Config.TrafficPolicy != TrafficPolicyBundleHosts || state.Config.PollInterval != 30 {
		t.Fatalf("the settings did not come from bootstrap: %+v", state.Config)
	}
}

func TestProxyTokenWithItsOwnCaReportsAndServesIt(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	own, err := LoadOwnCa(OwnCaInput{Cert: certPEM, Key: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	fakeBootstrap(t, func(w http.ResponseWriter, _ int32, req api.AgentVaultProxyBootstrapRequest) {
		if req.ServedCaCertificate != certPEM {
			t.Errorf("bootstrap did not report the CA this copy serves")
		}
		_ = json.NewEncoder(w).Encode(bootstrapResponse(nil))
	})

	_, ca, err := loadFromProxyToken("pxt", own)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca.RootPEM()) != certPEM {
		t.Fatal("the proxy does not serve the operator's CA")
	}
}

func TestProxyTokenRetriesUntilInfisicalAnswers(t *testing.T) {
	shortBootstrapRetries(t)
	certPEM, _, pkcs8 := caPairPEM(t)
	attempts := fakeBootstrap(t, func(w http.ResponseWriter, attempt int32, _ api.AgentVaultProxyBootstrapRequest) {
		if attempt < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(bootstrapResponse(&api.AgentVaultProxyRootCa{Certificate: certPEM, PrivateKey: pkcs8}))
	})

	if _, _, err := loadFromProxyToken("pxt", nil); err != nil {
		t.Fatalf("bootstrap gave up while Infisical was coming back: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestProxyTokenStopsRetryingAndDoesNotServe(t *testing.T) {
	shortBootstrapRetries(t)
	for _, status := range []int{http.StatusBadGateway, http.StatusTooManyRequests} {
		attempts := fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
			w.WriteHeader(status)
		})

		start := time.Now()
		_, ca, err := loadFromProxyToken("pxt", nil)
		if !errors.Is(err, errBootstrapUnreachable) {
			t.Fatalf("%d: expected the not-serving message, got %v", status, err)
		}
		if ca != nil {
			t.Fatalf("%d: a CA came back without a successful bootstrap", status)
		}
		if attempts.Load() < 2 {
			t.Fatalf("%d: gave up without retrying", status)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("%d: retried for %s, past the window", status, elapsed)
		}
	}
}

func TestProxyTokenExitsAtOnceOnAClientError(t *testing.T) {
	shortBootstrapRetries(t)
	for status, message := range map[int]string{
		http.StatusBadRequest:   "payments is a Standard proxy; enroll it with --enrollment-token",
		http.StatusUnauthorized: "Token rejected",
	} {
		attempts := fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"` + message + `"}`))
		})

		_, _, err := loadFromProxyToken("pxt", nil)
		var apiErr *api.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
			t.Fatalf("%d: expected the API error, got %v", status, err)
		}
		if !strings.Contains(err.Error(), message) {
			t.Fatalf("%d: the server's message was lost: %v", status, err)
		}
		if attempts.Load() != 1 {
			t.Fatalf("%d: a client error was retried %d times", status, attempts.Load())
		}
	}
}

func TestProxyTokenRefusesAnAnswerWithoutACa(t *testing.T) {
	fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
		_ = json.NewEncoder(w).Encode(bootstrapResponse(nil))
	})
	if _, ca, err := loadFromProxyToken("pxt", nil); err == nil || ca != nil {
		t.Fatal("bootstrap without a CA must not serve")
	}
}

func TestTickWithoutAStoreAppliesSettingsInMemory(t *testing.T) {
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

	loaded := persistedState{ProxyID: "p1", AccessToken: "pxt", Config: ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost, PollInterval: 60}}
	ps := &proxyServer{opts: Options{ProxyToken: func() string { return "pxt" }}, config: loaded.Config, persisted: loaded}
	resolver, err := newInfisicalResolver(ps.opts.ProxyToken)
	if err != nil {
		t.Fatal(err)
	}
	ps.cache = newSessionCache(resolver, ps.pollInterval)

	ps.tick(nil)

	if got := ps.currentConfig(); got.TrafficPolicy != TrafficPolicyBundleHosts || got.PollInterval != 30 {
		t.Fatalf("the new settings were not applied: %+v", got)
	}
}

func TestPollLoopWithoutAStoreSaysToUseTheCurrentProxyToken(t *testing.T) {
	ps, _ := newPollLoopFixture(t, http.StatusUnauthorized)
	stop := make(chan struct{})
	fatal := make(chan error, 1)
	done := runPollLoop(ps, nil, stop, fatal)

	select {
	case err := <-fatal:
		if err != errHaProxyTokenRejected {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("poll loop kept running after two 401 heartbeats")
	}
	<-done
}
