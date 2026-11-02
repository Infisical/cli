package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	infisicalSdk "github.com/infisical/go-sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sleepingClock replaces tokenNow and tokenSleep. A sleep advances the wall clock by its duration, and once
// the awake time passes suspendAt, the machine sleeps: the wall clock jumps by suspendFor while no timer
// moves, as Go's timers behave across a suspend.
type sleepingClock struct {
	mu         sync.Mutex
	now        time.Time
	awake      time.Duration
	suspendAt  time.Duration
	suspendFor time.Duration
	resumedAt  time.Time
	sleeps     []time.Duration
}

func (c *sleepingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *sleepingClock) Sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	if c.resumedAt.IsZero() && c.awake+d >= c.suspendAt {
		c.now = c.now.Add(c.suspendFor)
		c.resumedAt = c.now.Add(c.suspendAt - c.awake)
	}
	c.awake += d
	c.now = c.now.Add(d)
}

// pass moves both clocks by the time a request takes, so the loop cannot spin without time passing.
func (c *sleepingClock) pass(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.awake += d
	c.now = c.now.Add(d)
}

type tokenServerRequest struct {
	path     string
	at       time.Time
	rejected bool
}

// tokenServer issues tokens as Infisical does: a token expires after its TTL, and no refresh extends it
// past the max TTL of its login. It reads the time from the fake clock.
type tokenServer struct {
	clock    *sleepingClock
	ttl      time.Duration
	maxTTL   time.Duration
	mu       sync.Mutex
	issued   int
	expiry   map[string]time.Time
	maxEnd   map[string]time.Time
	requests []tokenServerRequest
}

func (s *tokenServer) issue(w http.ResponseWriter, now, maxEnd time.Time) {
	s.issued++
	token := fmt.Sprintf("token-%d", s.issued)
	expiry := now.Add(s.ttl)
	if expiry.After(maxEnd) {
		expiry = maxEnd
	}
	s.expiry[token], s.maxEnd[token] = expiry, maxEnd
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accessToken":       token,
		"expiresIn":         int(s.ttl.Seconds()),
		"accessTokenMaxTTL": int(s.maxTTL.Seconds()),
		"tokenType":         "Bearer",
	})
}

func (s *tokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock.pass(50 * time.Millisecond)
	now := s.clock.Now()
	switch {
	case strings.HasSuffix(r.URL.Path, "/v1/auth/universal-auth/login"):
		s.requests = append(s.requests, tokenServerRequest{path: "login", at: now})
		s.issue(w, now, now.Add(s.maxTTL))
	case strings.HasSuffix(r.URL.Path, "/v1/auth/token/renew"):
		var body struct {
			AccessToken string `json:"accessToken"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if expiry, ok := s.expiry[body.AccessToken]; !ok || !now.Before(expiry) {
			s.requests = append(s.requests, tokenServerRequest{path: "renew", at: now, rejected: true})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Your token has expired. Please re-authenticate."}`))
			return
		}
		s.requests = append(s.requests, tokenServerRequest{path: "renew", at: now})
		s.issue(w, now, s.maxEnd[body.AccessToken])
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *tokenServer) valid(token string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.expiry[token]
	return ok && at.Before(expiry)
}

// A laptop that sleeps for two hours in the middle of a token's life gets a valid token again within one
// tick of waking up, instead of after the rest of a long sleep and the retries of an expired token.
func TestAgentTokenIsValidAgainOneTickAfterTheMachineSleeps(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ttl, maxTTL time.Duration
	}{
		{name: "ttl equals max ttl", ttl: time.Hour, maxTTL: time.Hour},
		{name: "ttl shorter than max ttl", ttl: time.Hour, maxTTL: 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 11, 1, 21, 15, 0, 0, time.UTC)
			clock := &sleepingClock{now: start, suspendAt: 27 * time.Minute, suspendFor: 2 * time.Hour}
			server := &tokenServer{clock: clock, ttl: tc.ttl, maxTTL: tc.maxTTL, expiry: map[string]time.Time{}, maxEnd: map[string]time.Time{}}
			httpServer := httptest.NewServer(server)
			defer httpServer.Close()
			withMockInfisicalURL(t, httpServer.URL+"/api")
			t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME, "client-id")
			t.Setenv("INFISICAL_UNIVERSAL_CLIENT_SECRET", "client-secret")

			origNow, origSleep := tokenNow, tokenSleep
			t.Cleanup(func() { tokenNow, tokenSleep = origNow, origSleep })
			tokenNow = clock.Now

			notifications := make(chan bool)
			go func() {
				for range notifications {
				}
			}()
			defer close(notifications)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tm := &AgentManager{
				authConfigBytes:                []byte("{}"),
				authStrategy:                   util.AuthStrategy.UNIVERSAL_AUTH,
				newAccessTokenNotificationChan: notifications,
				infisicalClient:                infisicalSdk.NewInfisicalClient(ctx, infisicalSdk.Config{SiteUrl: httpServer.URL}),
			}

			// Run for six hours of wall time, and note each moment the agent holds an expired token.
			var invalidAt []time.Time
			tokenSleep = func(d time.Duration) {
				clock.Sleep(d)
				now := clock.Now()
				if !server.valid(tm.GetToken(), now) {
					invalidAt = append(invalidAt, now)
				}
				if now.After(start.Add(6 * time.Hour)) {
					tm.isShuttingDown = true
				}
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				tm.ManageTokenLifecycle()
			}()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("ManageTokenLifecycle did not reach six hours of fake time")
			}

			require.False(t, clock.resumedAt.IsZero(), "the machine never slept")
			for _, d := range clock.sleeps {
				assert.LessOrEqual(t, d, tokenLifecycleTick, "a sleep longer than one tick ends late after a suspend")
			}
			for _, at := range invalidAt {
				assert.WithinDuration(t, clock.resumedAt, at, tokenLifecycleTick, "the agent held an expired token long after the resume")
			}

			server.mu.Lock()
			defer server.mu.Unlock()
			var firstAfterResume *tokenServerRequest
			for i, req := range server.requests {
				assert.False(t, req.rejected, "the agent sent an expired token to renew at %s", req.at)
				if firstAfterResume == nil && !req.at.Before(clock.resumedAt) {
					firstAfterResume = &server.requests[i]
				}
			}
			require.NotNil(t, firstAfterResume, "the agent never called the server after the resume")
			assert.Equal(t, "login", firstAfterResume.path, "the token expired while asleep, so the agent must log in again")
			assert.WithinDuration(t, clock.resumedAt, firstAfterResume.at, tokenLifecycleTick)
		})
	}
}

func TestTokenNowCarriesNoMonotonicReading(t *testing.T) {
	// == rather than Equal: Equal ignores the monotonic reading, which pauses while the machine sleeps.
	now := tokenNow()
	assert.True(t, now == now.Round(0), "tokenNow carries a monotonic reading, so its deadlines ignore time asleep")
}
