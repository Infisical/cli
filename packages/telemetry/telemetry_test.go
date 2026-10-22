package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/posthog/posthog-go"
)

// fakePostHog records the body of every batch it receives.
type fakePostHog struct {
	*httptest.Server
	mu     sync.Mutex
	events []string
}

func (f *fakePostHog) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.events = append(f.events, string(body))
	f.mu.Unlock()
}

func (f *fakePostHog) received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func newFakePostHog(t *testing.T) *fakePostHog {
	t.Helper()
	f := &fakePostHog{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
	}))
	t.Cleanup(f.Close)
	return f
}

// hangingPostHog answers nothing until release is called, like a network that drops packets.
func hangingPostHog(t *testing.T) (server *fakePostHog, release func()) {
	t.Helper()
	unblock := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(unblock) }) }

	server = &fakePostHog{}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-unblock
		server.record(r)
	}))
	// Cleanups run last-in first-out: release the handler before the server waits on it.
	t.Cleanup(server.Close)
	t.Cleanup(release)
	return server, release
}

// isolate keeps the test away from the real config file, which an enabled capture can write to, and from
// any token in the environment that would change the distinct ID.
func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN", "")
	t.Setenv("INFISICAL_TOKEN", "")
	t.Setenv("TOKEN", "")
}

func newTestTelemetry(t *testing.T, endpoint string, enabled bool) *Telemetry {
	t.Helper()
	tel := newTelemetry("test-key", endpoint, enabled)
	tel.SetActor("identity-1", "org-1")
	return tel
}

func TestTelemetryEnabledSendsEvent(t *testing.T) {
	isolate(t)
	server := newFakePostHog(t)

	newTestTelemetry(t, server.URL, true).CaptureEvent("cli-command:test", posthog.NewProperties())

	got := server.received()
	if len(got) != 1 || !strings.Contains(got[0], "cli-command:test") {
		t.Fatalf("expected one batch carrying the event, got %q", got)
	}
}

func TestTelemetryDisabledSendsNothing(t *testing.T) {
	isolate(t)
	server := newFakePostHog(t)

	tel := newTestTelemetry(t, server.URL, true)
	tel.SetEnabled(false)
	tel.CaptureEvent("cli-command:test", posthog.NewProperties())

	if got := server.received(); len(got) != 0 {
		t.Fatalf("expected nothing sent after opting out, got %q", got)
	}
}

func TestTelemetryWithoutKeyStaysDisabled(t *testing.T) {
	isolate(t)

	tel := newTelemetry("", "", true)
	tel.SetEnabled(true)
	if tel.IsEnabled() {
		t.Fatal("a build without a PostHog key has no client and must stay disabled")
	}
	// Would dereference the missing client if the guard were wrong.
	tel.CaptureEvent("cli-command:test", posthog.NewProperties())
}
