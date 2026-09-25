package clickhouse

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// outcomeRecorder pairs a statement with how it ended. The two directions of a native session are read by
// separate goroutines, and ClickHouse answers statements in order, so the queue is what joins them back up.
//
// Reading the server direction is best effort: a block it cannot decode costs the outcome, never the statement.
// Once that happens the recorder degrades and every later statement is written as soon as it is sent.
type outcomeRecorder struct {
	proxy *ClickHouseProxy

	mu       sync.Mutex
	pending  []pendingStatement
	degraded bool
}

type pendingStatement struct {
	statement string
	started   time.Time
	rows      uint64
	bytes     uint64
}

func newOutcomeRecorder(proxy *ClickHouseProxy) *outcomeRecorder {
	return &outcomeRecorder{proxy: proxy}
}

func (r *outcomeRecorder) begin(statement string) {
	r.mu.Lock()
	if r.degraded {
		r.mu.Unlock()
		r.proxy.logStatement(statement, "SENT")
		return
	}
	r.pending = append(r.pending, pendingStatement{statement: statement, started: time.Now()})
	r.mu.Unlock()
}

// progress folds ClickHouse's running counters into the statement in flight.
func (r *outcomeRecorder) progress(rows uint64, bytes uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return
	}
	r.pending[0].rows += rows
	r.pending[0].bytes += bytes
}

func (r *outcomeRecorder) complete(outcome string) {
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return
	}
	next := r.pending[0]
	r.pending = r.pending[1:]
	r.mu.Unlock()

	r.proxy.logStatement(next.statement, next.describe(outcome))
}

func (p pendingStatement) describe(outcome string) string {
	parts := []string{outcome}
	if p.rows > 0 {
		parts = append(parts, fmt.Sprintf("%d row(s) read", p.rows))
	}
	return strings.Join(append(parts, fmt.Sprintf("%dms", time.Since(p.started).Milliseconds())), ", ")
}

// degrade stops pairing outcomes for the rest of the session and says so in the recording, so a log that
// carries outcomes for some statements and not others is never read as if the rest simply did nothing.
func (r *outcomeRecorder) degrade(reason string) {
	r.mu.Lock()
	if r.degraded {
		r.mu.Unlock()
		return
	}
	r.degraded = true
	drained := r.pending
	r.pending = nil
	r.mu.Unlock()

	note := fmt.Sprintf("SENT: the outcome could not be read (%s), so the rest of this session records "+
		"statements without one", reason)
	for _, statement := range drained {
		r.proxy.logStatement(statement.statement, note)
	}
}

func (r *outcomeRecorder) finish() {
	r.mu.Lock()
	drained := r.pending
	r.pending = nil
	r.mu.Unlock()

	for _, statement := range drained {
		r.proxy.logStatement(statement.statement, statement.describe("INTERRUPTED: the session ended first"))
	}
}
