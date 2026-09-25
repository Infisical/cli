package agentvault

import (
	"net/http"
	"net/http/httptest"
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
	if _, err := resolver.resolve("tok"); err == nil {
		t.Fatal("a 429 resolved successfully")
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("one resolve against a 429 made %d requests; retries belong to the poll loop, not the request path", got)
	}
}
