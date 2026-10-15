package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
// that the test can bump to simulate a change in that one source. Secret values follow the etag, so
// a rendered file changes with it. Dynamic secret lease creation hands out a new lease (and new data)
// on every call.
type mockEtagServer struct {
	mu           sync.Mutex
	etags        map[string]string
	listRequests int
	leaseCreates int
}

func (m *mockEtagServer) set(key, etag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.etags[key] = etag
}

func (m *mockEtagServer) listRequestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listRequests
}

func (m *mockEtagServer) leaseCreateCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.leaseCreates
}

func newMockEtagServer(t *testing.T) *mockEtagServer {
	t.Helper()
	m := &mockEtagServer{etags: map[string]string{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		secretPath := r.URL.Query().Get("secretPath")
		path := strings.TrimPrefix(r.URL.Path, "/api")
		w.Header().Set("Content-Type", "application/json")

		if path == "/v1/dynamic-secrets/leases" && r.Method == http.MethodPost {
			m.leaseCreates++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"lease":         map[string]any{"id": fmt.Sprintf("lease-%d", m.leaseCreates), "expireAt": time.Now().Add(time.Hour)},
				"dynamicSecret": map[string]any{},
				"data":          map[string]any{"TOKEN": fmt.Sprintf("token-%d", m.leaseCreates)},
			})
			return
		}

		if name, ok := strings.CutPrefix(path, "/v4/secrets/"); ok {
			w.Header().Set("etag", m.etags[name])
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secret": map[string]any{"secretKey": name, "secretValue": secretPath + ":" + m.etags[name]},
			})
			return
		}

		m.listRequests++
		w.Header().Set("etag", m.etags[secretPath])
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secrets": []map[string]any{{"secretKey": "KEY", "secretValue": secretPath + ":" + m.etags[secretPath]}},
			"imports": []any{},
		})
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL+"/api")
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

func TestTemplateEtag_DynamicSecretLease(t *testing.T) {
	const dynamicTemplate = `{{ with dynamicSecret "proj-slug" "dev" "/" "my-dynamic" "1h" }}{{ .TOKEN }}{{ end }}`

	m := newMockEtagServer(t)
	leases := NewDynamicSecretLeaseManager(nil, nil)
	agentManager := &AgentManager{}

	render := func() string {
		t.Helper()
		currentEtag := ""
		_, err := ProcessLiteralTemplate(1, dynamicTemplate, nil, "token", &currentEtag, leases, agentManager)
		require.NoError(t, err)
		return currentEtag
	}

	// first render creates the lease, second reuses the stored one: same lease data, so same etag,
	// otherwise every new lease would re-render and run the command a second time on the next poll
	withNewLease := render()
	withStoredLease := render()
	assert.NotEmpty(t, withNewLease)
	assert.Equal(t, withNewLease, withStoredLease)
	assert.Equal(t, 1, m.leaseCreateCount())

	// the lease goes away (expired and pruned), so the next render leases new credentials
	leases.leases = nil
	withRotatedLease := render()
	assert.Equal(t, 2, m.leaseCreateCount())
	assert.NotEqual(t, withNewLease, withRotatedLease)
}

func TestMonitorSecretChanges_RewritesOnlyWhenASourceChanges(t *testing.T) {
	m := newMockEtagServer(t)
	m.set("/first", "a1")
	m.set("/last", "b1")

	dir := t.TempDir()
	destination := filepath.Join(dir, "rendered.txt")
	counter := filepath.Join(dir, "command-runs.txt")

	var secretTemplate Template
	secretTemplate.TemplateContent = `{{ with listSecrets "proj" "dev" "/first" }}{{ range . }}{{ .Value }} {{ end }}{{ end }}` +
		`{{ with listSecrets "proj" "dev" "/last" }}{{ range . }}{{ .Value }}{{ end }}{{ end }}`
	secretTemplate.DestinationPath = destination
	secretTemplate.Config.PollingInterval = "100ms"
	secretTemplate.Config.Execute.Command = fmt.Sprintf(`echo x>> "%s"`, counter)

	tm := &AgentManager{
		accessToken:             "token",
		dynamicSecretLeases:     NewDynamicSecretLeaseManager(nil, nil),
		templateFirstRenderOnce: map[int]*sync.Once{1: {}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	firstRender := make(chan bool, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		tm.MonitorSecretChanges(ctx, secretTemplate, 1, make(chan os.Signal, 1), firstRender)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	commandRuns := func() int {
		content, err := os.ReadFile(counter)
		if err != nil {
			return 0
		}
		return strings.Count(string(content), "x")
	}
	rendered := func() string {
		content, _ := os.ReadFile(destination)
		return string(content)
	}
	// each poll makes two list requests; waiting on requests instead of time keeps the test steady
	waitForPolls := func(polls int) {
		t.Helper()
		target := m.listRequestCount() + 2*polls
		require.Eventually(t, func() bool { return m.listRequestCount() >= target }, 10*time.Second, 10*time.Millisecond)
	}

	select {
	case <-firstRender:
	case <-time.After(10 * time.Second):
		t.Fatal("template was never rendered")
	}
	assert.Equal(t, "/first:a1 /last:b1", rendered())
	assert.Equal(t, 0, commandRuns(), "first render does not run the command")

	waitForPolls(5)
	assert.Equal(t, 0, commandRuns(), "unchanged polls must not run the command")

	m.set("/first", "a2")
	require.Eventually(t, func() bool { return rendered() == "/first:a2 /last:b1" }, 10*time.Second, 10*time.Millisecond)
	waitForPolls(5)
	assert.Equal(t, 1, commandRuns(), "a change in an earlier fetch runs the command once")
}
