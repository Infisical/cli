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
	// A held packet is often a Ping, so the first step is small and the rest double from it.
	tapGrowthBytes = 512
)

var packetIdleTimeout = 2 * time.Minute

var errGatewayFull = errors.New("this gateway is already holding its share of ClickHouse packet " +
	"memory; try again, or send the data in smaller batches")

var nativeBytesInFlight atomic.Int64

type packetMemory struct{ held int64 }

func (m *packetMemory) take(n int) error {
	if nativeBytesInFlight.Add(int64(n)) > maxNativeBytesInFlight {
		nativeBytesInFlight.Add(-int64(n))
		return errGatewayFull
	}
	m.held += int64(n)
	return nil
}

func (m *packetMemory) giveBack() {
	nativeBytesInFlight.Add(-m.held)
	m.held = 0
}

// A relayed session arrives over an SSH channel, whose SetReadDeadline does nothing, so a stalled
// read is cut off by closing the connection instead of by the transport.
type idleTimer struct {
	after time.Duration
	conns []io.Closer

	mu       sync.Mutex
	timer    *time.Timer
	running  bool
	deadline time.Time
}

func newIdleTimer(after time.Duration, conns ...io.Closer) *idleTimer {
	it := &idleTimer{after: after, conns: conns}
	it.timer = time.AfterFunc(after, it.expire)
	it.timer.Stop()
	return it
}

func (it *idleTimer) reset() {
	it.mu.Lock()
	it.deadline = time.Now().Add(it.after)
	wasStopped := !it.running
	it.running = true
	it.mu.Unlock()

	if wasStopped {
		it.timer.Reset(it.after)
	}
}

func (it *idleTimer) stop() {
	it.mu.Lock()
	it.running = false
	it.mu.Unlock()
	it.timer.Stop()
}

// Stop cannot call back an expiry that has already begun, so the deadline is what decides: one that
// belongs to a packet already finished finds the timer stopped, and a reset one reschedules.
func (it *idleTimer) expire() {
	it.mu.Lock()
	if !it.running {
		it.mu.Unlock()
		return
	}
	if left := time.Until(it.deadline); left > 0 {
		it.mu.Unlock()
		it.timer.Reset(left)
		return
	}
	it.running = false
	it.mu.Unlock()

	for _, c := range it.conns {
		_ = c.Close()
	}
}
