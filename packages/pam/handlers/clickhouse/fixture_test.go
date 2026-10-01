package clickhouse

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/stretchr/testify/require"
)

func decodeNativeBlock(payload []byte) (proto.Block, proto.Results, int, error) {
	var (
		block   proto.Block
		decoded proto.Results
	)
	counting := &countingReader{src: payload}
	r := proto.NewReader(counting)
	r.SetLimit(maxPacketBytes)
	err := block.DecodeBlock(r, 0, decoded.Auto())
	return block, decoded, counting.read, err
}

func encodeResults(t *testing.T, block proto.Block, decoded proto.Results) []byte {
	t.Helper()

	input := make(proto.Input, 0, len(decoded))
	for _, c := range decoded {
		encodable, ok := c.Data.(proto.ColInput)
		require.True(t, ok, "column %q must be writable", c.Name)
		input = append(input, proto.InputColumn{Name: c.Name, Data: encodable})
	}
	var b proto.Buffer
	require.NoError(t, block.EncodeBlock(&b, 0, input))
	return b.Buf
}

// Column types the decoder cannot infer. They are refused at session time, and the point of listing
// them here is that they are refused rather than silently mis-parsed.
var unreadableFixtures = map[string]bool{
	"fixedstring.native":        true,
	"lc_nullable_string.native": true,
}

// Real ClickHouse blocks, so the boundary is not just ch-go agreeing with itself.
func TestDecodeAgreesWithClickHousesOwnBlocks(t *testing.T) {
	files, err := filepath.Glob("testdata/*.native")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			payload, err := os.ReadFile(file)
			require.NoError(t, err)

			block, decoded, read, decodeErr := decodeNativeBlock(payload)
			if unreadableFixtures[filepath.Base(file)] {
				require.Error(t, decodeErr, "an uninferable type must be refused, not mis-parsed")
				return
			}
			require.NoError(t, decodeErr)
			require.Equal(t, len(payload), read, "the decode must land on the block's last byte")

			// Re-encoding must be stable, or a block would change every time it passed through.
			once := encodeResults(t, block, decoded)
			block, decoded, read, err = decodeNativeBlock(once)
			require.NoError(t, err)
			require.Equal(t, len(once), read)
			require.Equal(t, once, encodeResults(t, block, decoded))
		})
	}
}
