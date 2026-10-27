package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

func TestRevokeAgentVaultSessionGivesUpAtTheDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = old })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := CallRevokeAgentVaultSession(ctx, resty.New().SetRetryCount(3), "session")
	if err == nil {
		t.Fatal("a revoke that never answered succeeded")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the revoke outlived its deadline by %s", time.Since(start))
	}
}
