package clickhouse

import (
	"fmt"

	"github.com/ClickHouse/ch-go/proto"
)

const (
	maxBlockRows    = 4 << 20
	maxBlockColumns = 4096
)

// Runs inside DecodeRawBlock after the header is read and before any column is allocated.
type boundedResult struct{ inner proto.Result }

func (b boundedResult) DecodeResult(r *proto.Reader, version int, block proto.Block) error {
	if block.Columns > maxBlockColumns {
		return fmt.Errorf("the data block declares %d columns, more than the %d this session accepts",
			block.Columns, maxBlockColumns)
	}
	if block.Rows > maxBlockRows {
		return fmt.Errorf("the data block declares %d rows, more than the %d this session accepts; "+
			"send the data in smaller batches", block.Rows, maxBlockRows)
	}
	return b.inner.DecodeResult(r, version, block)
}
