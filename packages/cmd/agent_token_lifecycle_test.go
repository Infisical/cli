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

// requestTime is how long the fake server takes to answer, so the loop cannot spin without time passing.
const requestTime = 50 * time.Millisecond

// fakeClock replaces tokenNow and tokenSleep. Sleeps and requests advance the true time, which the server
// reads, and the agent's wall clock with it. Once the awake time passes suspendAt, the machine sleeps: both
// jump by suspendFor while no timer moves, as Go's timers behave across a suspend. Once the awake time passes
// stepAt, a correction of the system time moves the agent's wall clock alone by stepBy.
type fakeClock struct {
	mu         sync.Mutex
	now        time.Time
	wallOffset time.Duration
	awake      time.Duration
	suspendAt  time.Duration
	suspendFor time.Duration
	stepAt     time.Duration
	stepBy     time.Duration
	resumedAt  time.Time
	sleeps     []time.Duration
}

// Wall is the agent's wall clock.
func (c *fakeClock) Wall() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Add(c.wallOffset)
}

// True is the time on the server.
func (c *fakeClock) True() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	c.advance(d)
}

func (c *fakeClock) pass(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance(d)
}

func (c *fakeClock) advance(d time.Duration) {
	if c.awake < c.suspendAt && c.suspendAt <= c.awake+d {
		c.now = c.now.Add(c.suspendFor)
		c.resumedAt = c.now.Add(c.suspendAt - c.awake)
	}
	if c.awake < c.stepAt && c.stepAt <= c.awake+d {
		c.wallOffset += c.stepBy
	}
	c.awake += d
	c.now = c.now.Add(d)
}

type tokenServerRequest struct {
	path     string
	at       time.Time
	rejected bool
}

// tokenServer issues tokens as Infisical does: a token expires after its TTL, and no renewal extends it
// past the max TTL of its login. It reads the true time from the fake clock.
type tokenServer struct {
	clock    *fakeClock
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
		"expiresIn":         int(expiry.Sub(now).Seconds()),
		"accessTokenMaxTTL": int(s.maxTTL.Seconds()),
		"tokenType":         "Bearer",
	})
}

func (s *tokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The response reaches the agent only after requestTime, so a suspend can fall between the two.
	defer s.clock.pass(requestTime)
	now := s.clock.True()
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

// runTokenLifecycle runs ManageTokenLifecycle for six hours of true time against a fake Infisical. It
// returns the server and each true time after a sleep at which the agent held an expired token.
func runTokenLifecycle(t *testing.T, clock *fakeClock, ttl, maxTTL time.Duration) (server *tokenServer, invalidAt []time.Time) {
	t.Helper()
	start := clock.True()
	server = &tokenServer{clock: clock, ttl: ttl, maxTTL: maxTTL, expiry: map[string]time.Time{}, maxEnd: map[string]time.Time{}}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	withMockInfisicalURL(t, httpServer.URL+"/api")
	t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME, "client-id")
	t.Setenv("INFISICAL_UNIVERSAL_CLIENT_SECRET", "client-secret")

	origNow, origSleep := tokenNow, tokenSleep
	t.Cleanup(func() { tokenNow, tokenSleep = origNow, origSleep })
	tokenNow = clock.Wall

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

	tokenSleep = func(d time.Duration) {
		clock.Sleep(d)
		now := clock.True()
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

	for _, d := range clock.sleeps {
		assert.LessOrEqual(t, d, tokenLifecycleTick, "a sleep longer than one tick ends late after a suspend")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, req := range server.requests {
		assert.False(t, req.rejected, "the agent sent an expired token to renew at %s", req.at)
	}
	return server, invalidAt
}

// A laptop that sleeps for two hours gets a valid token again within one tick of waking up, instead of
// after the rest of a long sleep and the retries of an expired token. This holds also when it sleeps
// while a response is on its way, after the server issued the token.
func TestAgentTokenIsValidAgainOneTickAfterTheMachineSleeps(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ttl, maxTTL time.Duration
		suspendAt   time.Duration
	}{
		{name: "ttl equals max ttl", ttl: time.Hour, maxTTL: time.Hour, suspendAt: 27 * time.Minute},
		{name: "ttl shorter than max ttl", ttl: time.Hour, maxTTL: 24 * time.Hour, suspendAt: 27 * time.Minute},
		{name: "during the login response", ttl: time.Hour, maxTTL: 24 * time.Hour, suspendAt: 10 * time.Millisecond},
		// The first renewal starts at 2/3 of the ttl.
		{name: "during the renew response", ttl: time.Hour, maxTTL: 24 * time.Hour, suspendAt: 40*time.Minute + 10*time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &fakeClock{now: time.Date(2026, 11, 1, 21, 15, 0, 0, time.UTC), suspendAt: tc.suspendAt, suspendFor: 2 * time.Hour}
			server, invalidAt := runTokenLifecycle(t, clock, tc.ttl, tc.maxTTL)

			require.False(t, clock.resumedAt.IsZero(), "the machine never slept")
			for _, at := range invalidAt {
				assert.WithinDuration(t, clock.resumedAt, at, tokenLifecycleTick, "the agent held an expired token long after the resume")
			}

			server.mu.Lock()
			defer server.mu.Unlock()
			var firstAfterResume *tokenServerRequest
			for i, req := range server.requests {
				if !req.at.Before(clock.resumedAt) {
					firstAfterResume = &server.requests[i]
					break
				}
			}
			require.NotNil(t, firstAfterResume, "the agent never called the server after the resume")
			assert.Equal(t, "login", firstAfterResume.path, "the token expired while asleep, so the agent must log in again")
			assert.WithinDuration(t, clock.resumedAt, firstAfterResume.at, tokenLifecycleTick)
		})
	}
}

// When a correction sets the system time back two hours, the agent still renews its one-hour token after
// 40 minutes, and not after 2 hours and 40 minutes.
func TestAgentTokenStaysValidWhenTheSystemTimeStepsBack(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 11, 1, 21, 15, 0, 0, time.UTC), stepAt: 10 * time.Minute, stepBy: -2 * time.Hour}
	_, invalidAt := runTokenLifecycle(t, clock, time.Hour, 24*time.Hour)

	assert.Empty(t, invalidAt, "the agent held an expired token")
}

func TestTokenNowCarriesNoMonotonicReading(t *testing.T) {
	// == rather than Equal: Equal ignores the monotonic reading, which pauses while the machine sleeps.
	now := tokenNow()
	assert.True(t, now == now.Round(0), "tokenNow carries a monotonic reading, so its deadlines ignore time asleep")
}
