package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

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
