package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// GenericRequestError does not unwrap, so the limit is matched by its message.
func TestAgentVaultCredentialCallsRefuseAnOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"` + strings.Repeat("x", agentVaultCredentialResponseLimit) + `"}`))
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	defer func() { config.INFISICAL_URL = old }()

	_, err := CallRefreshAgentVaultServiceCredential(resty.New(), "tok", "svc", RefreshAgentVaultServiceCredentialRequest{})
	if err == nil || !strings.Contains(err.Error(), resty.ErrResponseBodyTooLarge.Error()) {
		t.Fatalf("refresh err = %v, want the body limit", err)
	}
	err = CallReportAgentVaultServiceMissingScopes(resty.New(), "tok", "svc", ReportAgentVaultServiceMissingScopesRequest{})
	if err == nil || !strings.Contains(err.Error(), resty.ErrResponseBodyTooLarge.Error()) {
		t.Fatalf("report err = %v, want the body limit", err)
	}
}

func TestCreateAgentVaultSessionRequestSendsALabelOnlyWhenGiven(t *testing.T) {
	// Without --label the request body stays exactly what it was before sessions had labels.
	unlabeled, err := json.Marshal(CreateAgentVaultSessionRequest{AccessBundles: []string{"coding-agent"}, TTL: "never"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unlabeled), "label") {
		t.Errorf("want no label key, got %s", unlabeled)
	}

	labeled, err := json.Marshal(CreateAgentVaultSessionRequest{AccessBundles: []string{"coding-agent"}, TTL: "never", Label: "nightly deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(labeled), `"label":"nightly deploy"`) {
		t.Errorf("want the label in the body, got %s", labeled)
	}
}
