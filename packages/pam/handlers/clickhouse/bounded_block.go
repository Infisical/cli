package clickhouse

import (
	"bufio"
	"encoding/binary"
	"fmt"
)

// ch-go allocates declared rows before reading, which recover cannot catch.
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

// Best-effort: anything unparseable falls through to ch-go rather than being refused.
func checkBlockHeader(src *bufio.Reader, revision int, compressed bool) string {
	// Compressed frames are already capped by ch-go.
	if compressed {
		return ""
	}

	// Peek only what has arrived; a fixed window would stall on a small block.
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
