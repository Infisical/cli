package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
)

func TestIsInstanceAlreadySetUpFromServerResponse(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"current server", http.StatusBadRequest, `{"statusCode":400,"message":"Instance has already been set up","error":"SUPER_ADMIN_INSTANCE_ALREADY_SET_UP"}`, true},
		{"server before v0.167.15", http.StatusBadRequest, `{"statusCode":400,"message":"Instance has already been set up","error":"BadRequest"}`, true},
		{"user already exists", http.StatusBadRequest, `{"statusCode":400,"message":"User already exists","error":"Instance initialization"}`, false},
		{"invalid setup token", http.StatusForbidden, `{"statusCode":403,"message":"The activation token is missing or incorrect.","error":"SUPER_ADMIN_INVALID_ACTIVATION_TOKEN"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			_, err := api.CallBootstrapInstance(resty.New(), api.BootstrapInstanceRequest{Domain: server.URL})
			if got := isInstanceAlreadySetUp(err); got != tt.want {
				t.Fatalf("isInstanceAlreadySetUp = %v, want %v (err: %v)", got, tt.want, err)
			}
		})
	}
}

func TestBootstrapRequestSetupToken(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantField bool
	}{
		{"sent when set", "setup-token", true},
		{"omitted when empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()

			if _, err := api.CallBootstrapInstance(resty.New(), api.BootstrapInstanceRequest{Domain: server.URL, SetupToken: tt.token}); err != nil {
				t.Fatalf("CallBootstrapInstance: %v", err)
			}

			got, present := body["setupToken"]
			if present != tt.wantField {
				t.Fatalf("setupToken present = %v, want %v", present, tt.wantField)
			}
			if tt.wantField && got != tt.token {
				t.Errorf("setupToken = %v, want %q", got, tt.token)
			}
		})
	}
}
