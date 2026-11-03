package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/spf13/cobra"
)

func buildNamespacedSecretsCmd() *cobra.Command {
	secretsCmd := buildSecretsCmd()
	namespaceSecretsCmd(secretsCmd)
	return secretsCmd
}

// A token pasted without NAME= must not be printed back, in text or in JSON.
func TestSecretWriteDoesNotRepeatAMalformedArgument(t *testing.T) {
	pasted := "test secret value"
	for _, action := range []string{"create", "update"} {
		for _, output := range [][]string{nil, {"-o", "json"}} {
			args := append([]string{"secrets", action, "A=1", pasted, "--projectId", testProjectID}, output...)
			stderr, _, exited := runUnderSecretsManager(t, buildNamespacedSecretsCmd, args...)
			if !exited || strings.Contains(stderr, pasted) || !strings.Contains(stderr, "Argument 2 isn't in NAME=value form") {
				t.Errorf("%s %v: exited=%v stderr=%q", action, output, exited, stderr)
			}
			if output != nil && errorCode(t, stderr) != errCodeInvalidArgument {
				t.Errorf("%s -o json: %s", action, stderr)
			}
		}
	}
}

const tokenProjectID = "0b9e4f1a-2c3d-4e5f-8a7b-6c5d4e3f2a1b"

// fakeServiceTokenAPI is a service token for tokenProjectID whose project has EXISTING=same.
type fakeServiceTokenAPI struct {
	mu       sync.Mutex
	requests []string
}

func (f *fakeServiceTokenAPI) serve(t *testing.T) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/service-token":
			_, _ = w.Write([]byte(`{"_id":"st","workspace":"` + tokenProjectID + `","scopes":[{"environment":"dev","secretPath":"/"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v4/secrets":
			_, _ = w.Write([]byte(`{"secrets":[{"_id":"s1","id":"s1","secretKey":"EXISTING","secretValue":"same","type":"shared"}],"imports":[]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(server.Close)
	orig := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = orig })
}

func (f *fakeServiceTokenAPI) reads(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, request := range f.requests {
		if request == http.MethodGet+" "+path {
			return true
		}
	}
	return false
}

// A service token always reads its own project, so with another project selected, update would
// compare the wrong project's values and could report an unchanged secret without writing anything.
func TestSecretWriteRefusesAServiceTokenForAnotherProject(t *testing.T) {
	selections := map[string]func(){
		"--projectId":          nil,
		"INFISICAL_PROJECT_ID": func() { t.Setenv(util.INFISICAL_PROJECT_ID_NAME, testProjectID) },
		".infisical.yaml": func() {
			if err := os.WriteFile(util.INFISICAL_WORKSPACE_CONFIG_FILE_NAME, []byte("secrets-management:\n  project-id: "+testProjectID+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, selectProject := range selections {
		for _, action := range []string{"create", "update"} {
			fake := &fakeServiceTokenAPI{}
			fake.serve(t)
			setup := func() {
				t.Setenv(util.INFISICAL_TOKEN_NAME, "st.id.secret.key")
				if selectProject != nil {
					selectProject()
				}
			}
			args := []string{"secrets", action, "EXISTING=same", "-o", "json"}
			if selectProject == nil {
				args = append(args, "--projectId", testProjectID)
			}
			stderr, stdout, exited := runUnderSecretsManagerAfter(t, setup, buildNamespacedSecretsCmd, args...)
			if !exited || errorCode(t, stderr) != errCodeTokenProjectMismatch || stdout != "" {
				t.Errorf("%s, %s: exited=%v stdout=%q stderr=%s", name, action, exited, stdout, stderr)
			}
			if fake.reads("/v4/secrets") {
				t.Errorf("%s, %s: secrets were read after the mismatch", name, action)
			}
		}
	}
}

func TestSecretWriteUsesTheServiceTokenProject(t *testing.T) {
	fake := &fakeServiceTokenAPI{}
	fake.serve(t)
	setup := func() { t.Setenv(util.INFISICAL_TOKEN_NAME, "st.id.secret.key") }
	stderr, _, exited := runUnderSecretsManagerAfter(t, setup, buildNamespacedSecretsCmd, "secrets", "update", "EXISTING=same", "-o", "json")
	if exited || !fake.reads("/v4/secrets") {
		t.Errorf("exited=%v stderr=%s", exited, stderr)
	}
}
