package agentvault

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// deadlineWriter is the half of an http.ResponseWriter that http.ResponseController reaches for.
type deadlineWriter struct {
	http.ResponseWriter
	deadlines []time.Time
}

func (d *deadlineWriter) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

// A response's write deadline is absolute and set once, at request start, so a stream that outlives it is
// cut while it is still producing. Every chunk has to push it out again.
func TestEachStreamedChunkPushesTheWriteDeadlineOut(t *testing.T) {
	rec := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	w := flushingWriter{ResponseWriter: rec, rc: http.NewResponseController(rec)}

	for i := 0; i < 3; i++ {
		if _, err := io.WriteString(w, "chunk\n"); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	if len(rec.deadlines) != 3 {
		t.Fatalf("expected one deadline per chunk, got %d", len(rec.deadlines))
	}
	for i := 1; i < len(rec.deadlines); i++ {
		if !rec.deadlines[i].After(rec.deadlines[i-1]) {
			t.Fatalf("chunk %d did not push the deadline out: %v then %v", i, rec.deadlines[i-1], rec.deadlines[i])
		}
	}
	// The deadline is an idle window, not a countdown to a fixed end.
	if got := time.Until(rec.deadlines[len(rec.deadlines)-1]); got < streamIdleTimeout-time.Second {
		t.Fatalf("last deadline is only %v away, want about %v", got, streamIdleTimeout)
	}
}
