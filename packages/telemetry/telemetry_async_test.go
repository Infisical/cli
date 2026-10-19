package telemetry

import (
	"strings"
	"testing"
	"time"

	"github.com/posthog/posthog-go"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
)

// waitForDelivery also keeps the test alive until the background send is done with HOME, which isolate
// points at a temporary directory only for the life of the test.
func waitForDelivery(t *testing.T, server *fakePostHog) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(server.received()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the background send never delivered the event")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return server.received()
}

func TestTelemetryCaptureEventAsyncDoesNotWait(t *testing.T) {
	isolate(t)
	server, release := hangingPostHog(t)

	start := time.Now()
	newTestTelemetry(t, server.URL, true).CaptureEventAsync("cli-command:test", posthog.NewProperties())
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("CaptureEventAsync waited %s on an unresponsive PostHog", elapsed)
	}

	// The event still goes out once PostHog answers.
	release()
	if got := waitForDelivery(t, server); !strings.Contains(got[0], "cli-command:test") {
		t.Fatalf("unexpected batch %q", got[0])
	}
}

func TestTelemetryCaptureEventAsyncWritesConfigBeforeReturning(t *testing.T) {
	isolate(t)
	server, release := hangingPostHog(t)
	if err := util.WriteConfigFile(&models.ConfigFile{LoggedInUserEmail: "dev@example.com"}); err != nil {
		t.Fatal(err)
	}

	newTestTelemetry(t, server.URL, true).CaptureEventAsync("cli-command:test", posthog.NewProperties())

	// Already written, while the send is still stuck: a process exiting now cannot interrupt the write.
	configFile, err := util.GetConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if configFile.LastIdentifiedEmail != "dev@example.com" {
		t.Fatalf("LastIdentifiedEmail = %q when CaptureEventAsync returned, want it written by then", configFile.LastIdentifiedEmail)
	}

	release()
	waitForDelivery(t, server)
}

func TestTelemetryCaptureEventAsyncDisabledSendsNothing(t *testing.T) {
	isolate(t)
	server := newFakePostHog(t)

	tel := newTestTelemetry(t, server.URL, false)
	tel.CaptureEventAsync("cli-command:test", posthog.NewProperties())

	time.Sleep(200 * time.Millisecond)
	if got := server.received(); len(got) != 0 {
		t.Fatalf("expected nothing sent after opting out, got %q", got)
	}
}
