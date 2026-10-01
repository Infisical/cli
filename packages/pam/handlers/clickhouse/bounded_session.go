package clickhouse

import (
	"fmt"
	"sync/atomic"
)

const (
	// One packet. The protocol's decoders allocate a declared length before reading it, so the
	// reader is given this limit and refuses anything larger before allocating it.
	maxPacketBytes = 64 << 20
	// All native sessions on this gateway together, so many connections cannot add up to the
	// machine's memory however little each one asks for.
	maxNativeBytesInFlight = 256 << 20
)

var nativeBytesInFlight atomic.Int64

// packetBudget draws this gateway's share of memory for one packet, and gives it back afterwards.
type packetBudget struct{ held int64 }

func (p *packetBudget) acquire() error {
	if nativeBytesInFlight.Add(maxPacketBytes) > maxNativeBytesInFlight {
		nativeBytesInFlight.Add(-maxPacketBytes)
		return fmt.Errorf("this gateway is already using its %d bytes for ClickHouse packets", maxNativeBytesInFlight)
	}
	p.held = maxPacketBytes
	return nil
}

func (p *packetBudget) release() {
	nativeBytesInFlight.Add(-p.held)
	p.held = 0
}
