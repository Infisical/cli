package clickhouse

import (
	"testing"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/stretchr/testify/require"
)

type recordingResult struct{ called bool }

func (r *recordingResult) DecodeResult(*proto.Reader, int, proto.Block) error {
	r.called = true
	return nil
}

func TestBoundedResultEnforcesTheBlockLimits(t *testing.T) {
	for _, c := range []struct {
		name    string
		block   proto.Block
		wantErr string
	}{
		{"within limits", proto.Block{Columns: 8, Rows: 1_048_545}, ""},
		{"at the row limit", proto.Block{Columns: 1, Rows: maxBlockRows}, ""},
		{"at the column limit", proto.Block{Columns: maxBlockColumns, Rows: 1}, ""},
		{"over the row limit", proto.Block{Columns: 1, Rows: maxBlockRows + 1}, "rows"},
		{"over the column limit", proto.Block{Columns: maxBlockColumns + 1, Rows: 1}, "columns"},
	} {
		t.Run(c.name, func(t *testing.T) {
			inner := &recordingResult{}
			err := boundedResult{inner}.DecodeResult(nil, maxNativeRevision, c.block)
			if c.wantErr == "" {
				require.NoError(t, err)
				require.True(t, inner.called, "a block within limits must reach the decoder")
				return
			}
			require.ErrorContains(t, err, c.wantErr)
			require.False(t, inner.called, "an over-limit block must be refused before the decoder runs")
		})
	}
}

func blockHeader(columns, rows uint64) []byte {
	var b proto.Buffer
	b.PutUVarInt(1)
	b.PutBool(false)
	b.PutUVarInt(2)
	b.PutInt32(-1)
	b.PutUVarInt(0)
	b.PutUVarInt(columns)
	b.PutUVarInt(rows)
	return b.Buf
}

// Wires the limit to the packet path, which the unit test above cannot see.
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
