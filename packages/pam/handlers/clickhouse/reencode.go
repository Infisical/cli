package clickhouse

import (
	"github.com/ClickHouse/ch-go/compress"
	"github.com/ClickHouse/ch-go/proto"
)

// encodeDataPacket writes the block back from what was decoded, so the bytes ClickHouse reads are
// the gateway's own rather than the client's.
func encodeDataPacket(
	rev int, table string, block proto.Block, decoded proto.Results, compressor *compress.Writer,
) ([]byte, error) {
	input, err := decoded.Input()
	if err != nil {
		return nil, err
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
