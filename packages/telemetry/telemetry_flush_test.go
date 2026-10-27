package telemetry

import (
	"testing"
	"time"

	"github.com/posthog/posthog-go"
)

func TestTelemetryCaptureEventGivesUpAfterFlushTimeout(t *testing.T) {
	isolate(t)
	server, _ := hangingPostHog(t)

	original := flushTimeout
	flushTimeout = 200 * time.Millisecond
	t.Cleanup(func() { flushTimeout = original })

	start := time.Now()
	newTestTelemetry(t, server.URL, true).CaptureEvent("cli-command:test", posthog.NewProperties())
	elapsed := time.Since(start)

	if elapsed < flushTimeout {
		t.Fatalf("returned after %s, before the %s cap; the send was not waited on", elapsed, flushTimeout)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("waited %s on an unresponsive PostHog despite the %s cap", elapsed, flushTimeout)
	}
}
