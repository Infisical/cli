package clickhouse

import (
	"fmt"

	"github.com/ClickHouse/ch-go/compress"
	"github.com/ClickHouse/ch-go/proto"
)

// A decoded column reports a lossier type than the server declared, so the declared one is written
// back: Decimal(10, 2) would otherwise become Decimal64.
type declaredColumn struct {
	proto.ColInput
	declared proto.ColumnType
}

func (c declaredColumn) Type() proto.ColumnType { return c.declared }

// Forwarded, or a column that carries either, such as LowCardinality, is written back without it.

func (c declaredColumn) EncodeState(b *proto.Buffer) {
	if v, ok := c.ColInput.(proto.StateEncoder); ok {
		v.EncodeState(b)
	}
}

func (c declaredColumn) Prepare() error {
	if v, ok := c.ColInput.(proto.Preparable); ok {
		return v.Prepare()
	}
	return nil
}

// encodeDataPacket writes the block back from what was decoded, so the bytes ClickHouse reads are
// the gateway's own rather than the client's.
func encodeDataPacket(
	rev int, table string, block proto.Block, decoded proto.Results, compressor *compress.Writer,
) ([]byte, error) {
	input := make(proto.Input, 0, len(decoded))
	for _, column := range decoded {
		encodable, ok := column.Data.(proto.ColInput)
		if !ok {
			return nil, fmt.Errorf("column %q cannot be written back", column.Name)
		}
		input = append(input, proto.InputColumn{
			Name: column.Name,
			Data: declaredColumn{ColInput: encodable, declared: column.Type},
		})
	}

	var b proto.Buffer
	proto.ClientCodeData.Encode(&b)
	b.PutString(table)

	start := len(b.Buf)
	if err := block.EncodeBlock(&b, rev, input); err != nil {
		return nil, err
	}
	if compressor != nil {
		if err := compressor.Compress(b.Buf[start:]); err != nil {
			return nil, err
		}
		b.Buf = append(b.Buf[:start], compressor.Data...)
	}
	return b.Buf, nil
}
