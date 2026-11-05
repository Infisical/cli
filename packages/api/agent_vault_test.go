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
	unlabeled, err := json.Marshal(CreateAgentVaultSessionRequest{AccessBundle: "coding-agent", TTL: "never"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unlabeled), "label") {
		t.Errorf("want no label key, got %s", unlabeled)
	}

	labeled, err := json.Marshal(CreateAgentVaultSessionRequest{AccessBundle: "coding-agent", TTL: "never", Label: "nightly deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(labeled), `"label":"nightly deploy"`) {
		t.Errorf("want the label in the body, got %s", labeled)
	}
}

func TestCreateAgentVaultSessionRejectsAnEmptySession(t *testing.T) {
	// An auth proxy redirects the POST to its login page, which answers 200 with HTML.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>sign in</html>"))
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	defer func() { config.INFISICAL_URL = old }()

	res, err := CallCreateAgentVaultSession(resty.New(), CreateAgentVaultSessionRequest{AccessBundles: []string{"coding-agent"}, TTL: "5m"})
	if err == nil {
		t.Fatalf("a login page was accepted as a session: %+v", res)
	}
	if !strings.Contains(err.Error(), "no session") {
		t.Errorf("err = %v, want it to say no session was returned", err)
	}
}

func TestCreateAgentVaultSessionReturnsTheMintedSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session":{"id":"sess-1","token":"tok-1","expiresAt":null}}`))
	}))
	defer srv.Close()
	old := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL
	defer func() { config.INFISICAL_URL = old }()

	res, err := CallCreateAgentVaultSession(resty.New(), CreateAgentVaultSessionRequest{AccessBundles: []string{"coding-agent"}, TTL: "never"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Session.ID != "sess-1" || res.Session.Token != "tok-1" {
		t.Errorf("session = %+v, want id sess-1 and token tok-1", res.Session)
	}
}

func TestCreateAgentVaultSessionRejectsAPartlyEmptySession(t *testing.T) {
	for name, body := range map[string]string{
		"id only":    `{"session":{"id":"sess-1","token":""}}`,
		"token only": `{"session":{"id":"","token":"tok-1"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			old := config.INFISICAL_URL
			config.INFISICAL_URL = srv.URL
			defer func() { config.INFISICAL_URL = old }()

			if _, err := CallCreateAgentVaultSession(resty.New(), CreateAgentVaultSessionRequest{AccessBundles: []string{"coding-agent"}, TTL: "5m"}); err == nil {
				t.Fatal("a session missing its id or token was accepted")
			}
		})
	}
}
