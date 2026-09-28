package clickhouse

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/stretchr/testify/require"
)

// blockHeader builds the wire prefix of a Data block body: BlockInfo, then columns and rows.
func blockHeader(columns, rows uint64) []byte {
	var b proto.Buffer
	b.PutUVarInt(blockInfoOverflows)
	b.PutBool(false)
	b.PutUVarInt(blockInfoBucketNum)
	b.PutInt32(-1)
	b.PutUVarInt(blockInfoEnd)
	b.PutUVarInt(columns)
	b.PutUVarInt(rows)
	return b.Buf
}

func scan(payload []byte, compressed bool) string {
	return checkBlockHeader(bufio.NewReaderSize(bytes.NewReader(payload), 64<<10), maxNativeRevision, compressed)
}

func TestBlockHeaderScanRefusesAnOversizedBlock(t *testing.T) {
	// ch-go allocates rows x width before reading, so this is committed memory, not a recoverable panic.
	reason := scan(blockHeader(1, 100_000_000), false)
	require.Contains(t, reason, "rows")
	require.Contains(t, reason, "smaller batches")

	require.Contains(t, scan(blockHeader(1_000_000, 1), false), "columns")
}

func TestBlockHeaderScanPassesALegitimateBlock(t *testing.T) {
	for _, c := range []struct {
		name          string
		columns, rows uint64
	}{
		{"an empty block", 0, 0},
		{"a single row", 1, 1},
		{"a default max_insert_block_size batch", 8, 1_048_545},
		{"exactly at the row cap", 1, maxBlockRows},
		{"exactly at the column cap", maxBlockColumns, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			require.Empty(t, scan(blockHeader(c.columns, c.rows), false))
		})
	}
}

// The scan must never be the thing that rejects traffic: anything it cannot parse is left to the decoder.
func TestBlockHeaderScanFallsThroughWhenItCannotParse(t *testing.T) {
	require.Empty(t, scan(nil, false), "empty input")
	require.Empty(t, scan([]byte{0xFF}, false), "a truncated varint")
	require.Empty(t, scan([]byte{0x09, 0x01}, false), "an unknown BlockInfo field")
	require.Empty(t, scan(blockHeader(1, 100_000_000), true), "a compressed block is ch-go's to bound")
}

// The bytes the scan inspects must still reach the decoder, or the packet would be truncated.
func TestBlockHeaderScanConsumesNothing(t *testing.T) {
	payload := append(blockHeader(2, 7), []byte("trailing")...)
	src := bufio.NewReaderSize(bytes.NewReader(payload), 64<<10)

	require.Empty(t, checkBlockHeader(src, maxNativeRevision, false))

	got := make([]byte, len(payload))
	_, err := src.Read(got[:1])
	require.NoError(t, err)
	require.Equal(t, payload[0], got[0], "the scan must not consume the header")
	require.Equal(t, len(payload)-1, src.Buffered()+0, "everything after the first byte is still pending")
}

// The whole point: a client must not be able to make the gateway size a column from a declared row count.
func TestNativeRefusesAnOversizedDataBlock(t *testing.T) {
	upstream := startFakeClickHouse(t)

	conn := dialProxy(t, ClickHouseProxyConfig{
		NativeAddr:    upstream.addr(),
		Username:      "account",
		SessionID:     "unit",
		SessionLogger: &recordingLogger{},
	})
	r := clientHandshake(t, conn, "someone", "whatever")

	var b proto.Buffer
	proto.ClientCodeData.Encode(&b)
	b.PutString("")
	b.Buf = append(b.Buf, blockHeader(1, 100_000_000)...)
	_, err := conn.Write(b.Buf)
	require.NoError(t, err)

	code, message := decodeException(t, r)
	require.Equal(t, codeNotImplemented, code)
	require.Contains(t, message, "rows")

	_, _, queries, bytesAfter := upstream.snapshot()
	require.Empty(t, queries)
	require.Zero(t, bytesAfter, "a refused block must not be relayed upstream")
}
