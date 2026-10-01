package clickhouse

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// The decoders allocate a declared length before reading it, so the reader is given this
	// limit and refuses anything larger before allocating it.
	maxPacketBytes = 64 << 20
	// Overrunning this degrades to a raw relay rather than ending the session, so ClickHouse's own
	// answers get a far more generous bound than anything a client sends.
	maxServerPacketBytes   = 256 << 20
	maxNativeBytesInFlight = 512 << 20
	deadlineRefreshBytes   = 1 << 20
	tapGrowthBytes         = 64 << 10
)

var packetIdleTimeout = 2 * time.Minute

var errGatewayFull = errors.New("this gateway is already holding its share of ClickHouse packet " +
	"memory; try again, or send the data in smaller batches")

var nativeBytesInFlight atomic.Int64

type packetAccount struct{ held int64 }

func (a *packetAccount) charge(n int) error {
	if nativeBytesInFlight.Add(int64(n)) > maxNativeBytesInFlight {
		nativeBytesInFlight.Add(-int64(n))
		return errGatewayFull
	}
	a.held += int64(n)
	return nil
}

func (a *packetAccount) release() {
	nativeBytesInFlight.Add(-a.held)
	a.held = 0
}

// A relayed session arrives over an SSH channel, whose SetReadDeadline does nothing, so a stalled
// read is cut off by closing the connection instead of by the transport.
type stallGuard struct {
	after time.Duration
	conns []io.Closer

	mu       sync.Mutex
	timer    *time.Timer
	armed    bool
	deadline time.Time
}

func newStallGuard(after time.Duration, conns ...io.Closer) *stallGuard {
	g := &stallGuard{after: after, conns: conns}
	g.timer = time.AfterFunc(after, g.fire)
	g.timer.Stop()
	return g
}

func (g *stallGuard) arm() {
	g.mu.Lock()
	g.deadline = time.Now().Add(g.after)
	resting := !g.armed
	g.armed = true
	g.mu.Unlock()

	if resting {
		g.timer.Reset(g.after)
	}
}

func (g *stallGuard) disarm() {
	g.mu.Lock()
	g.armed = false
	g.mu.Unlock()
	g.timer.Stop()
}

// Stop cannot call back a firing that has already begun, so the deadline is what decides: one that
// belongs to a packet already finished finds the guard at rest, and a refreshed one reschedules.
func (g *stallGuard) fire() {
	g.mu.Lock()
	if !g.armed {
		g.mu.Unlock()
		return
	}
	if left := time.Until(g.deadline); left > 0 {
		g.mu.Unlock()
		g.timer.Reset(left)
		return
	}
	g.armed = false
	g.mu.Unlock()

	for _, c := range g.conns {
		_ = c.Close()
	}
}
