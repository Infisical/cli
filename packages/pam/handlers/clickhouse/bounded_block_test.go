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
