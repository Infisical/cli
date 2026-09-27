package agentvault

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
)

func TestAResolveDoesNotRetryA429WhileTheAgentWaits(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"statusCode":429,"message":"Too many requests","error":"RateLimit"}`))
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	defer func() { config.INFISICAL_URL = old }()

	resolver, err := newInfisicalResolver(func() string { return "ptok" })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.resolve("tok", nil); err == nil {
		t.Fatal("a 429 resolved successfully")
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("one resolve against a 429 made %d requests; retries belong to the poll loop, not the request path", got)
	}
}

func TestAResolveAsksForTheKeyUntilItHoldsOne(t *testing.T) {
	key := aKey(7)
	var mu sync.Mutex
	var asked []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			HasSessionLogKey bool `json:"hasSessionLogKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("the resolve body did not decode: %v", err)
		}
		mu.Lock()
		asked = append(asked, body.HasSessionLogKey)
		mu.Unlock()

		sessionKey := ""
		if !body.HasSessionLogKey {
			sessionKey = base64.StdEncoding.EncodeToString(key)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sessionId":   "s1",
			"services":    []any{},
			"sessionLogs": map[string]any{"enabled": true, "sessionKey": sessionKey},
		})
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	defer func() { config.INFISICAL_URL = old }()

	resolver, err := newInfisicalResolver(func() string { return "ptok" })
	if err != nil {
		t.Fatal(err)
	}

	first, err := resolver.resolve("tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.SessionLog == nil || string(first.SessionLog.key) != string(key) {
		t.Fatal("the first resolve did not come back with the key Infisical sent")
	}

	again, err := resolver.resolve("tok", first.SessionLog)
	if err != nil {
		t.Fatal(err)
	}
	if again.SessionLog == nil || string(again.SessionLog.key) != string(key) {
		t.Fatal("the key was lost once the proxy said it already held it")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 2 || asked[0] || !asked[1] {
		t.Fatalf("hasSessionLogKey went out as %v; it must be false until the proxy holds the key, then true", asked)
	}
}
