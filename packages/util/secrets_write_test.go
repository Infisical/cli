package util

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
)

// A repeated key is refused before any request: without a server to answer, reaching the network would
// return a different error.
func TestWriteRawSecretsRefusesRepeatedKeysBeforeWriting(t *testing.T) {
	for _, mode := range []SecretWriteMode{SecretWriteCreateOnly, SecretWriteUpdateOnly} {
		_, err := WriteRawSecrets(mode, []string{"DUP=a", "OTHER=b", "DUP=b"}, SECRET_TYPE_SHARED, "dev", "/", "project", &models.TokenDetails{}, "", nil)
		var repeated *SecretWriteRepeated
		if !errors.As(err, &repeated) || repeated.Key != "DUP" {
			t.Errorf("mode %d: got %v", mode, err)
		}
	}
}

// A .env file becomes a map that keeps the last of repeated keys, so the repeat has to be found in the
// file itself.
func TestWriteRawSecretsRefusesRepeatedKeysInADotenvFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(file, []byte("# comment\nDUP=a\nOTHER=b\n DUP = b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []SecretWriteMode{SecretWriteCreateOnly, SecretWriteUpdateOnly} {
		_, err := WriteRawSecrets(mode, nil, SECRET_TYPE_SHARED, "dev", "/", "project", &models.TokenDetails{}, file, nil)
		var repeated *SecretWriteRepeated
		if !errors.As(err, &repeated) || repeated.Key != "DUP" {
			t.Errorf("mode %d: got %v", mode, err)
		}
	}
}

// fakeSecretsAPI answers the routes WriteRawSecrets calls. The project has one shared secret,
// EXISTING, and no tags. Every request is recorded.
type fakeSecretsAPI struct {
	expiredServiceToken bool
	mu                  sync.Mutex
	requests            []string
}

func (f *fakeSecretsAPI) serve(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/service-token" && f.expiredServiceToken:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"UnauthorizedError","message":"Token expired","reqId":"req-test"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v4/secrets":
			_, _ = w.Write([]byte(`{"secrets":[{"_id":"s1","id":"s1","secretKey":"EXISTING","secretValue":"old","type":"shared"}],"imports":[]}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tags/slug/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"NotFound","message":"tag not found","reqId":"req-test"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tags"):
			_, _ = w.Write([]byte(`{"workspaceTag":{"id":"tag-1","slug":"team"},"tag":{"id":"tag-1","slug":"team"}}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(server.Close)
	orig := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = orig })
}

// writes is every request that creates or changes something, tags included.
func (f *fakeSecretsAPI) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var writes []string
	for _, request := range f.requests {
		if !strings.HasPrefix(request, http.MethodGet) {
			writes = append(writes, request)
		}
	}
	return writes
}

var identityToken = &models.TokenDetails{Type: UNIVERSAL_AUTH_TOKEN_IDENTIFIER, Token: "identity-access-token"}

// The point of create and update: when a key is on the wrong side, nothing at all is written, not even
// the tag from --tag.
func TestWriteRawSecretsConflictSendsNoWrites(t *testing.T) {
	cases := []struct {
		mode SecretWriteMode
		args []string
		want string
	}{
		{SecretWriteCreateOnly, []string{"NEW=1", "EXISTING=2"}, "EXISTING"},
		{SecretWriteUpdateOnly, []string{"EXISTING=2", "MISSING=1"}, "MISSING"},
	}
	for _, c := range cases {
		fake := &fakeSecretsAPI{}
		fake.serve(t)
		_, err := WriteRawSecrets(c.mode, c.args, SECRET_TYPE_SHARED, "dev", "/", "project", identityToken, "", []string{"team"})
		var conflict *SecretWriteConflict
		if !errors.As(err, &conflict) || len(conflict.Keys) != 1 || conflict.Keys[0] != c.want {
			t.Errorf("mode %d: got %v", c.mode, err)
		}
		if writes := fake.writes(); len(writes) != 0 {
			t.Errorf("mode %d: a refused write sent %v", c.mode, writes)
		}
	}
}

func TestWriteRawSecretsWritesWhatItWasAsked(t *testing.T) {
	cases := []struct {
		mode SecretWriteMode
		args []string
		want []string
	}{
		{SecretWriteCreateOnly, []string{"NEW=1"}, []string{"POST /v1/projects/project/tags", "POST /v3/secrets/raw/NEW"}},
		{SecretWriteUpdateOnly, []string{"EXISTING=2"}, []string{"POST /v1/projects/project/tags", "PATCH /v3/secrets/raw/EXISTING"}},
		{SecretWriteUpsert, []string{"NEW=1", "EXISTING=2"}, []string{"POST /v1/projects/project/tags", "POST /v3/secrets/raw/NEW", "PATCH /v3/secrets/raw/EXISTING"}},
	}
	for _, c := range cases {
		fake := &fakeSecretsAPI{}
		fake.serve(t)
		if _, err := WriteRawSecrets(c.mode, c.args, SECRET_TYPE_SHARED, "dev", "/", "project", identityToken, "", []string{"team"}); err != nil {
			t.Errorf("mode %d: %v", c.mode, err)
		}
		if got := strings.Join(fake.writes(), ", "); got != strings.Join(c.want, ", ") {
			t.Errorf("mode %d: sent [%s], want [%s]", c.mode, got, strings.Join(c.want, ", "))
		}
	}
}

// An expired service token fails while reading the token's details. That API error must stay
// reachable, so create and update can report it as auth_required.
func TestWriteRawSecretsKeepsServiceTokenAPIErrors(t *testing.T) {
	fake := &fakeSecretsAPI{expiredServiceToken: true}
	fake.serve(t)
	serviceToken := &models.TokenDetails{Type: SERVICE_TOKEN_IDENTIFIER, Token: "st.id.secret.key"}
	_, err := WriteRawSecrets(SecretWriteCreateOnly, []string{"NEW=1"}, SECRET_TYPE_SHARED, "dev", "/", "project", serviceToken, "", nil)
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %v", err)
	}
	if !strings.Contains(err.Error(), "unable to retrieve secrets") {
		t.Errorf("the message must read as before: %v", err)
	}
}
