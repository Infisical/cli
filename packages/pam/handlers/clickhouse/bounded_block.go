package clickhouse

import (
	"bufio"
	"encoding/binary"
	"fmt"
)

// ch-go sizes a column from the declared row count before it reads any of it: ColInt64.DecodeColumn does
// make([]int64, rows) and only then blocks in ReadFull. Its own ceiling is 100M rows, so a ~30 byte header
// commits 763 MB for Int64 and 3.2 GB for Int256 while the client sends nothing further. That allocation
// succeeds, so unlike an oversized string it is not a panic the handler can recover from.
const (
	maxBlockRows    = 4 << 20
	maxBlockColumns = 4096
	// BlockInfo plus two varints; anything past this is the decoder's problem.
	blockHeaderWindow = 64
)

// blockInfo field ids, from ch-go's proto/block.go.
const (
	blockInfoOverflows = 1
	blockInfoBucketNum = 2
	blockInfoEnd       = 0
)

// checkBlockHeader inspects the block header without consuming it and reports a reason to refuse. The scan
// is best-effort on purpose: anything it cannot parse returns "", leaving the real decoder to judge, so a
// mistake here can only miss an attack and never reject legitimate traffic.
func checkBlockHeader(src *bufio.Reader, revision int, compressed bool) string {
	// Compressed blocks arrive as LZ4 frames, which these raw bytes are not, and ch-go already caps a
	// compressed frame at maxDataSize.
	if compressed {
		return ""
	}

	// Peek only what has already arrived. A fixed size would block until that many bytes exist, which
	// stalls a session whose next block is smaller than the window.
	if _, err := src.Peek(1); err != nil {
		return ""
	}
	window := src.Buffered()
	if window > blockHeaderWindow {
		window = blockHeaderWindow
	}
	head, err := src.Peek(window)
	if err != nil && len(head) == 0 {
		return ""
	}

	p := &peeker{buf: head}
	if featureBlockInfo(revision) && !p.skipBlockInfo() {
		return ""
	}

	columns, ok := p.uvarint()
	if !ok {
		return ""
	}
	rows, ok := p.uvarint()
	if !ok {
		return ""
	}

	if columns > maxBlockColumns {
		return fmt.Sprintf("the data block declares %d columns, more than the %d this session accepts",
			columns, maxBlockColumns)
	}
	if rows > maxBlockRows {
		return fmt.Sprintf("the data block declares %d rows, more than the %d this session accepts. "+
			"Send the data in smaller batches", rows, maxBlockRows)
	}
	return ""
}

// FeatureBlockInfo is 51903 in ch-go; every revision this proxy speaks is above it, but keep the gate
// explicit so the scan stays aligned with DecodeBlock.
func featureBlockInfo(revision int) bool { return revision >= 51903 }

type peeker struct {
	buf []byte
	pos int
}

func (p *peeker) byteAt() (byte, bool) {
	if p.pos >= len(p.buf) {
		return 0, false
	}
	b := p.buf[p.pos]
	p.pos++
	return b, true
}

func (p *peeker) uvarint() (uint64, bool) {
	v, n := binary.Uvarint(p.buf[p.pos:])
	if n <= 0 {
		return 0, false
	}
	p.pos += n
	return v, true
}

// Mirrors BlockInfo.Decode: field-id/value pairs terminated by field 0.
func (p *peeker) skipBlockInfo() bool {
	for {
		field, ok := p.uvarint()
		if !ok {
			return false
		}
		switch field {
		case blockInfoEnd:
			return true
		case blockInfoOverflows:
			if _, ok := p.byteAt(); !ok {
				return false
			}
		case blockInfoBucketNum:
			if p.pos+4 > len(p.buf) {
				return false
			}
			p.pos += 4
		default:
			return false
		}
	}
}
