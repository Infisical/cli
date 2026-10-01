package clickhouse

import "time"

const (
	// The decoders allocate a declared length before reading it, so the reader is given this
	// limit and refuses anything larger before allocating it.
	maxPacketBytes = 64 << 20
	// Generous for the largest packet accepted, and far shorter than an idle session's lifetime.
	packetDeadline = 2 * time.Minute
)
