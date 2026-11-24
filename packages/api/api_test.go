package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
)

// The error label must match the operation that sent the request.
func TestCallGetSecretsV4ErrorNamesTheV4Operation(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	prev := config.INFISICAL_URL
	config.INFISICAL_URL = srv.URL + "/api"
	t.Cleanup(func() { config.INFISICAL_URL = prev })

	_, err := CallGetSecretsV4(resty.New(), GetSecretsV4Request{
		WorkspaceId: "workspace-id",
		Environment: "dev",
		SecretPath:  "/",
	})
	if err == nil {
		t.Fatal("expected an error from a 500 response")
	}
	if gotPath != "/api/v4/secrets" {
		t.Fatalf("request went to %q, want /api/v4/secrets", gotPath)
	}
	if !strings.HasPrefix(err.Error(), "CallGetSecretsV4 ") {
		t.Fatalf("error should start with the CallGetSecretsV4 operation label, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "CallGetRawSecretsV3") {
		t.Fatalf("error %q names a v3 operation for a /v4/secrets request", err.Error())
	}
}
