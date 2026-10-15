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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On Windows t.TempDir() returns a backslash path, which regressed with
// "is an incomplete or empty template" when the template name was derived with path.Base.
func TestProcessTemplate_RendersFileFromSourcePath(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "runlist.tmpl")
	require.NoError(t, os.WriteFile(templatePath, []byte(`greeting={{ "hello" | upper }}`), 0600))

	currentEtag := ""
	rendered, err := ProcessTemplate(1, templatePath, nil, "", &currentEtag, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "greeting=HELLO", rendered.String())
}

// mockEtagServer serves /v4/secrets with a per-path etag (and /v4/secrets/<name> with a per-name etag)
// that the test can bump to simulate a change in that one source.
type mockEtagServer struct {
	mu    sync.Mutex
	etags map[string]string
}

func (m *mockEtagServer) set(key, etag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.etags[key] = etag
}

func newMockEtagServer(t *testing.T) *mockEtagServer {
	t.Helper()
	m := &mockEtagServer{etags: map[string]string{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		secretPath := r.URL.Query().Get("secretPath")
		w.Header().Set("Content-Type", "application/json")

		if name, ok := strings.CutPrefix(r.URL.Path, "/v4/secrets/"); ok {
			w.Header().Set("etag", m.etags[name])
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secret": map[string]any{"secretKey": name, "secretValue": secretPath},
			})
			return
		}

		w.Header().Set("etag", m.etags[secretPath])
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secrets": []map[string]any{{"secretKey": "KEY", "secretValue": secretPath}},
			"imports": []any{},
		})
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)
	return m
}

// renderTemplateEtag renders the template the way MonitorSecretChanges does and returns the combined etag.
func renderTemplateEtag(t *testing.T, templateString string) string {
	t.Helper()
	currentEtag := ""
	_, err := ProcessLiteralTemplate(1, templateString, nil, "token", &currentEtag, nil, nil)
	require.NoError(t, err)
	return currentEtag
}

func TestTemplateEtag_DetectsChangeInAnyFetch(t *testing.T) {
	const multiPathTemplate = `{{ with listSecrets "proj" "dev" "/football" }}{{ range . }}{{ .Value }}{{ end }}{{ end }}
{{ with listSecrets "proj" "dev" "/football/my-app" }}{{ range . }}{{ .Value }}{{ end }}{{ end }}`

	t.Run("change in a non-last listSecrets path", func(t *testing.T) {
		m := newMockEtagServer(t)
		m.set("/football", "a1")
		m.set("/football/my-app", "b1")

		initial := renderTemplateEtag(t, multiPathTemplate)
		assert.Equal(t, initial, renderTemplateEtag(t, multiPathTemplate), "no source changed")

		m.set("/football", "a2")
		assert.NotEqual(t, initial, renderTemplateEtag(t, multiPathTemplate), "change under /football must be detected")
	})

	t.Run("change in the last listSecrets path", func(t *testing.T) {
		m := newMockEtagServer(t)
		m.set("/football", "a1")
		m.set("/football/my-app", "b1")

		initial := renderTemplateEtag(t, multiPathTemplate)
		m.set("/football/my-app", "b2")
		assert.NotEqual(t, initial, renderTemplateEtag(t, multiPathTemplate))
	})

	t.Run("change in getSecretByName followed by listSecrets", func(t *testing.T) {
		const mixedTemplate = `{{ with getSecretByName "proj" "dev" "/" "DB_PASSWORD" }}{{ .Value }}{{ end }}
{{ with listSecrets "proj" "dev" "/app" }}{{ range . }}{{ .Value }}{{ end }}{{ end }}`

		m := newMockEtagServer(t)
		m.set("DB_PASSWORD", "s1")
		m.set("/app", "l1")

		initial := renderTemplateEtag(t, mixedTemplate)
		assert.Equal(t, initial, renderTemplateEtag(t, mixedTemplate))

		m.set("DB_PASSWORD", "s2")
		assert.NotEqual(t, initial, renderTemplateEtag(t, mixedTemplate))
	})

	t.Run("single fetch template", func(t *testing.T) {
		const singleTemplate = `{{ with listSecrets "proj" "dev" "/app" }}{{ range . }}{{ .Value }}{{ end }}{{ end }}`

		m := newMockEtagServer(t)
		m.set("/app", "l1")

		initial := renderTemplateEtag(t, singleTemplate)
		assert.Equal(t, initial, renderTemplateEtag(t, singleTemplate))

		m.set("/app", "l2")
		assert.NotEqual(t, initial, renderTemplateEtag(t, singleTemplate))
	})
}
