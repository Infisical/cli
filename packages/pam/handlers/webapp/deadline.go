package webapp

import (
	"sync"
	"time"
)

type leaseClock struct {
	mu       sync.Mutex
	hard     time.Time
	grace    time.Duration
	timer    *time.Timer
	done     chan struct{}
	closed   bool
	deadline time.Time
}

func newLeaseClock(hard, until time.Time, grace time.Duration) *leaseClock {
	now := time.Now()
	l := &leaseClock{hard: now.Add(hard.Sub(now)), grace: grace, done: make(chan struct{})}
	l.timer = time.AfterFunc(time.Hour, l.expire)
	l.Renew(until)
	return l
}

func (l *leaseClock) expire() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed && time.Until(l.deadline) > 0 {
		l.timer.Reset(time.Until(l.deadline))
		return
	}
	if !l.closed {
		l.closed = true
		close(l.done)
	}
}

func (l *leaseClock) Renew(until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		remaining := max(0, min(time.Until(until)+l.grace, time.Until(l.hard)))
		l.deadline = time.Now().Add(remaining)
		l.timer.Reset(remaining)
	}
}

func (l *leaseClock) Stop() { l.mu.Lock(); defer l.mu.Unlock(); l.timer.Stop(); l.closed = true }

func (l *leaseClock) Deadline() time.Time { l.mu.Lock(); defer l.mu.Unlock(); return l.deadline }
