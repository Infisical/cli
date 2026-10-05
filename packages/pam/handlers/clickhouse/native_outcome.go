package clickhouse

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type outcomeRecorder struct {
	proxy *ClickHouseProxy

	mu       sync.Mutex
	pending  []pendingStatement
	degraded bool
	// The newest statement, and whether it already has an outcome. A statement drained by degrade
	// has none, which is what lets a refusal still be attributed to it.
	last         string
	lastResolved bool
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

func forLog(statement string) string {
	if len(statement) <= maxLoggedStatementBytes {
		return statement
	}
	return statement[:maxLoggedStatementBytes] + "... [truncated]"
}

func (r *outcomeRecorder) begin(statement string) {
	// Only what a recording can hold: the rest would be kept for the life of the session and never
	// written anywhere.
	statement = forLog(statement)

	r.mu.Lock()
	r.last, r.lastResolved = statement, false
	if r.degraded {
		r.mu.Unlock()
		r.proxy.logStatement(statement, "SENT")
		return
	}
	r.pending = append(r.pending, pendingStatement{statement: statement, started: time.Now()})
	r.mu.Unlock()
}

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
	if len(r.pending) == 0 {
		r.lastResolved = true
	}
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

// The gateway knows a refusal first hand, so it is recorded even once the outcome reader has given
// up on this session and stopped pairing.
func (r *outcomeRecorder) refuse(reason string) {
	r.mu.Lock()
	var pending *pendingStatement
	if len(r.pending) > 0 {
		next := r.pending[0]
		r.pending = r.pending[1:]
		pending = &next
	}
	statement := r.last
	if pending != nil || !r.lastResolved {
		r.lastResolved = true
	} else {
		statement = ""
	}
	r.mu.Unlock()

	if pending != nil {
		r.proxy.logStatement(pending.statement, pending.describe("REFUSED: "+reason))
		return
	}
	if statement == "" {
		return
	}
	r.proxy.logStatement(statement, "REFUSED: "+reason)
}

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
