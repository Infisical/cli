package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// A repeated name is local input, so it's refused before any request: an expired token or an API that
// can't be reached must not hide it.
func TestSecretWriteRefusesRepeatedNamesBeforeAnyRequest(t *testing.T) {
	dir := t.TempDir()
	dotenv := dir + "/repeated.env"
	if err := os.WriteFile(dotenv, []byte("DUP=a\nDUP=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]string{"arguments": {"DUP=a", "DUP=b"}, "--file": {"--file", dotenv}}
	tokens := map[string]string{"service token": "st.id.secret.key", "machine identity": "identity-access-token"}
	for tokenName, token := range tokens {
		for inputName, input := range inputs {
			for _, action := range []string{"create", "update"} {
				fake := &fakeServiceTokenAPI{}
				fake.serve(t)
				setup := func() { t.Setenv(util.INFISICAL_TOKEN_NAME, token) }
				args := append([]string{"secrets", action, "-o", "json", "--projectId", tokenProjectID}, input...)
				stderr, _, exited := runUnderSecretsManagerAfter(t, setup, buildNamespacedSecretsCmd, args...)
				if !exited || errorCode(t, stderr) != errCodeInvalidArgument {
					t.Errorf("%s, %s, %s: exited=%v stderr=%s", tokenName, inputName, action, exited, stderr)
				}
				if len(fake.requests) != 0 {
					t.Errorf("%s, %s, %s: sent %v", tokenName, inputName, action, fake.requests)
				}
			}
		}
	}
}

// Arguments that can't be written are refused from the input alone, so a --tag is never created for a
// write that then fails. The value is never repeated: it can be a pasted credential.
func TestSecretWriteRefusesArgumentsThatCantBeWrittenBeforeAnyRequest(t *testing.T) {
	cases := map[string]struct {
		arg  string
		want string
	}{
		"no value": {"NEW=", `Secret "NEW" has no value: pass it as NAME=value or NAME=@filepath. Nothing was written.`},
		"no name":  {"=hunter2-value", "Argument 1 has no secret name: pass it as NAME=value. Nothing was written."},
		// quoted shows a name that isn't a valid one as <name>, so a pasted token can't reach the message.
		"name starts with digit": {"1KEY=hunter2-value", "Secret name <name> starts with a number: secret names must start with a letter or an underscore. Nothing was written."},
	}
	for name, c := range cases {
		for _, action := range []string{"create", "update"} {
			fake := &fakeServiceTokenAPI{}
			fake.serve(t)
			setup := func() { t.Setenv(util.INFISICAL_TOKEN_NAME, "identity-access-token") }
			stderr, _, exited := runUnderSecretsManagerAfter(t, setup, buildNamespacedSecretsCmd,
				"secrets", action, c.arg, "--tag", "newtag", "--projectId", tokenProjectID, "-o", "json")
			var failure struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			_ = json.Unmarshal([]byte(stderr), &failure)
			if !exited || errorCode(t, stderr) != errCodeInvalidArgument || failure.Error.Message != c.want || strings.Contains(stderr, "hunter2") {
				t.Errorf("%s, %s: exited=%v stderr=%s", name, action, exited, stderr)
			}
			if len(fake.requests) != 0 {
				t.Errorf("%s, %s: sent %v", name, action, fake.requests)
			}
		}
	}
}

// For create and update, a --file that can't be written from is an invalid_flag_value document on
// stderr with -o json, sent before any request, and never repeats a value from the file.
func TestSecretWriteFileProblemsAreStructured(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	files := map[string]string{
		"missing":     filepath.Join(dir, "missing.env"),
		"unparsable":  write("bad.yaml", "A: [hunter2-value\n"),
		"invalid key": write("digit.env", "1KEY=hunter2-value\n"),
		"empty value": write("empty.env", "NEW=\n"),
		"no secrets":  write("nothing.env", "# comment\n"),
	}
	for name, file := range files {
		for _, action := range []string{"create", "update"} {
			fake := &fakeServiceTokenAPI{}
			fake.serve(t)
			setup := func() { t.Setenv(util.INFISICAL_TOKEN_NAME, "identity-access-token") }
			stderr, _, exited := runUnderSecretsManagerAfter(t, setup, buildNamespacedSecretsCmd,
				"secrets", action, "--file", file, "--projectId", tokenProjectID, "-o", "json")
			var failure struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stderr), &failure); err != nil || !exited || failure.Error.Code != errCodeInvalidFlagValue ||
				!strings.HasSuffix(failure.Error.Message, "Nothing was written.") || strings.Contains(stderr, "hunter2") {
				t.Errorf("%s, %s: exited=%v stderr=%s", name, action, exited, stderr)
			}
			if len(fake.requests) != 0 {
				t.Errorf("%s, %s: sent %v", name, action, fake.requests)
			}
		}
	}
}

// --plain prints only values, one per line, for the secrets-manager listing as it does for names. The
// top-level `infisical secrets --plain` keeps its NAME=value lines.
func TestPlainListingPrintsValues(t *testing.T) {
	setup := func() { t.Setenv(util.INFISICAL_TOKEN_NAME, "identity-access-token") }
	fake := &fakeServiceTokenAPI{}
	fake.serve(t)
	_, stdout, exited := runUnderSecretsManagerAfter(t, setup, buildNamespacedSecretsCmd, "secrets", "get", "--plain", "--projectId", tokenProjectID)
	if exited || stdout != "same\n" {
		t.Errorf("secrets-manager secrets get --plain: exited=%v stdout=%q", exited, stdout)
	}
	fake = &fakeServiceTokenAPI{}
	fake.serve(t)
	_, stdout, exited = runUnderSecretsManagerAfter(t, setup, buildSecretsCmd, "secrets", "--plain", "--projectId", tokenProjectID)
	if exited || stdout != "EXISTING=same\n" {
		t.Errorf("top-level secrets --plain: exited=%v stdout=%q", exited, stdout)
	}
}
