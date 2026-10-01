package clickhouse

import (
	"errors"
	"io"
	"sync/atomic"
	"time"
)

const (
	// The decoders allocate a declared length before reading it, so the reader is given this
	// limit and refuses anything larger before allocating it.
	maxPacketBytes = 64 << 20
	// What every native session on this gateway may hold at once. Charged as a packet is read
	// rather than reserved up front, so a session that sends nothing holds nothing.
	maxNativeBytesInFlight = 512 << 20
	// How often an arriving packet refreshes that guard.
	deadlineRefreshBytes = 1 << 20
)

// How long a packet may go without delivering anything. Refreshed as bytes arrive, so a slow link
// finishes a large insert while a silent one gives its memory back. A variable for the tests.
var packetIdleTimeout = 2 * time.Minute

// Named so a refusal says the gateway ran out of room rather than blaming the packet for it.
var errGatewayFull = errors.New("this gateway is already holding its share of ClickHouse packet " +
	"memory; try again, or send the data in smaller batches")

var nativeBytesInFlight atomic.Int64

// packetAccount holds what one packet has charged against the gateway's share, and gives it back
// once the packet is done with it.
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
	timer *time.Timer
	after time.Duration
}

func newStallGuard(after time.Duration, conns ...io.Closer) *stallGuard {
	g := &stallGuard{after: after}
	g.timer = time.AfterFunc(after, func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	g.timer.Stop()
	return g
}

func (g *stallGuard) arm()    { g.timer.Reset(g.after) }
func (g *stallGuard) disarm() { g.timer.Stop() }
