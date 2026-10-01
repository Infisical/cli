package clickhouse

import (
	"errors"
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
	// How long a packet may go without delivering anything. Refreshed as bytes arrive, so a slow
	// link finishes a large insert while a silent one gives its memory back.
	packetIdleTimeout = 2 * time.Minute
	// How often an arriving packet refreshes that deadline, which costs a syscall each time.
	deadlineRefreshBytes = 1 << 20
)

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
