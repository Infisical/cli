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
