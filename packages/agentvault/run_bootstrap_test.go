package agentvault

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

func shortBootstrapRetries(t *testing.T) {
	t.Helper()
	prevWindow, prevUnauthorized, prevBackoff := bootstrapRetryWindow, bootstrapUnauthorizedWindow, bootstrapFirstBackoff
	bootstrapRetryWindow, bootstrapUnauthorizedWindow, bootstrapFirstBackoff = 500*time.Millisecond, 150*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() {
		bootstrapRetryWindow, bootstrapUnauthorizedWindow, bootstrapFirstBackoff = prevWindow, prevUnauthorized, prevBackoff
	})
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
		http.StatusBadRequest: "servedCaCertificate is not a valid certificate",
		http.StatusForbidden:  "Forbidden",
		http.StatusNotFound:   "Agent Vault proxy not found",
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
		if err != errProxyTokenRejected {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("poll loop kept running after two 401 heartbeats")
	}
	<-done
}

func TestProxyTokenSendsNoServedCaKeyWithoutItsOwnCa(t *testing.T) {
	certPEM, _, pkcs8 := caPairPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("the body is not a JSON object: %q", raw)
		}
		if _, ok := body["servedCaCertificate"]; ok {
			t.Errorf("servedCaCertificate was sent with no CA of its own: %s", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bootstrapResponse(&api.AgentVaultProxyRootCa{Certificate: certPEM, PrivateKey: pkcs8}))
	}))
	t.Cleanup(srv.Close)
	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	t.Cleanup(func() { config.INFISICAL_URL = prev })

	if _, _, err := loadFromProxyToken("pxt", nil); err != nil {
		t.Fatal(err)
	}
}

func TestProxyTokenRefusesUnusableSettings(t *testing.T) {
	certPEM, _, pkcs8 := caPairPEM(t)
	for name, cfg := range map[string]api.AgentVaultProxyConfig{
		"empty answer":     {},
		"unknown policy":   {TrafficPolicy: "deny", PollInterval: 30},
		"no poll interval": {TrafficPolicy: TrafficPolicyBundleHosts},
	} {
		fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
			res := bootstrapResponse(&api.AgentVaultProxyRootCa{Certificate: certPEM, PrivateKey: pkcs8})
			res.Config = cfg
			_ = json.NewEncoder(w).Encode(res)
		})
		_, ca, err := loadFromProxyToken("pxt", nil)
		if err == nil || ca != nil || !strings.Contains(err.Error(), "no usable proxy settings") {
			t.Fatalf("%s: unusable settings were served: %v", name, err)
		}
	}
}

func TestBootstrapAttemptTimeoutNeverDropsBelowTheFloor(t *testing.T) {
	for remaining, want := range map[time.Duration]time.Duration{
		-5 * time.Second:         bootstrapMinTimeout,
		0:                        bootstrapMinTimeout,
		time.Millisecond:         bootstrapMinTimeout,
		5 * time.Second:          5 * time.Second,
		10 * controlPlaneTimeout: controlPlaneTimeout,
	} {
		if got := bootstrapAttemptTimeout(remaining); got != want {
			t.Fatalf("remaining %s: timeout %s, want %s", remaining, got, want)
		}
	}
}

func TestBootstrapBacksOffAndGivesUpWithinTheWindow(t *testing.T) {
	shortBootstrapRetries(t)
	var mu sync.Mutex
	var waits []time.Duration
	prevSleep := bootstrapSleep
	bootstrapSleep = func(d time.Duration) {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		time.Sleep(d)
	}
	t.Cleanup(func() { bootstrapSleep = prevSleep })
	fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	start := time.Now()
	_, _, err := loadFromProxyToken("pxt", nil)
	elapsed := time.Since(start)
	if !errors.Is(err, errBootstrapUnreachable) {
		t.Fatalf("expected the not-serving message, got %v", err)
	}
	if elapsed > bootstrapRetryWindow+500*time.Millisecond {
		t.Fatalf("retried for %s, past the %s window", elapsed, bootstrapRetryWindow)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(waits) < 3 {
		t.Fatalf("expected at least 3 backoffs, got %v", waits)
	}
	if waits[0] != bootstrapFirstBackoff {
		t.Fatalf("first backoff %s, want %s", waits[0], bootstrapFirstBackoff)
	}
	for i := 1; i < len(waits); i++ {
		if waits[i] != min(waits[i-1]*2, bootstrapMaxBackoff) {
			t.Fatalf("backoff did not double: %v", waits)
		}
	}
	var slept time.Duration
	for _, d := range waits {
		slept += d
	}
	if slept > bootstrapRetryWindow {
		t.Fatalf("slept %s in total, past the %s window", slept, bootstrapRetryWindow)
	}
}

func TestBootstrapGivesUpBeforeSendingWhenNoTimeIsLeft(t *testing.T) {
	shortBootstrapRetries(t)
	prevSleep := bootstrapSleep
	bootstrapSleep = func(time.Duration) { time.Sleep(bootstrapRetryWindow) }
	t.Cleanup(func() { bootstrapSleep = prevSleep })
	attempts := fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
		w.WriteHeader(http.StatusBadGateway)
	})

	_, _, err := loadFromProxyToken("pxt", nil)
	if !errors.Is(err, errBootstrapUnreachable) {
		t.Fatalf("expected the not-serving message, got %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("a request was sent after the window closed: %d attempts", attempts.Load())
	}
}

func TestBootstrapRetriesARejectedTokenBrieflyThenFails(t *testing.T) {
	shortBootstrapRetries(t)
	attempts := fakeBootstrap(t, func(w http.ResponseWriter, _ int32, _ api.AgentVaultProxyBootstrapRequest) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Token rejected"}`))
	})

	start := time.Now()
	_, _, err := loadFromProxyToken("pxt", nil)
	elapsed := time.Since(start)
	if !errors.Is(err, errProxyTokenRejected) {
		t.Fatalf("expected the rejected-token message, got %v", err)
	}
	if attempts.Load() < 2 {
		t.Fatalf("a 401 was not retried: %d attempts", attempts.Load())
	}
	if elapsed < bootstrapUnauthorizedWindow || elapsed > bootstrapRetryWindow {
		t.Fatalf("gave up on the 401 after %s; want about %s", elapsed, bootstrapUnauthorizedWindow)
	}
}

func TestBootstrapRidesOutAReplicaThatHasNotSeenTheTokenYet(t *testing.T) {
	shortBootstrapRetries(t)
	certPEM, _, pkcs8 := caPairPEM(t)
	attempts := fakeBootstrap(t, func(w http.ResponseWriter, attempt int32, _ api.AgentVaultProxyBootstrapRequest) {
		if attempt < 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(bootstrapResponse(&api.AgentVaultProxyRootCa{Certificate: certPEM, PrivateKey: pkcs8}))
	})

	if _, _, err := loadFromProxyToken("pxt", nil); err != nil {
		t.Fatalf("bootstrap gave up on a token the replica had not seen yet: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts.Load())
	}
}
