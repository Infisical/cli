package clickhouse

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTapRelaysWhatItHasAlreadyBuffered(t *testing.T) {
	upstreamRead, upstreamWrite := net.Pipe()
	defer upstreamRead.Close()
	defer upstreamWrite.Close()

	payload := bytes.Repeat([]byte("abcdefghij"), 20) // 200 bytes in one burst
	go func() {
		_, _ = upstreamWrite.Write(payload)
		upstreamWrite.Close()
	}()

	tp := newTap(upstreamRead)

	// Consume 10 bytes through the tap, as a decoder would before it fails.
	consumed := make([]byte, 10)
	_, err := io.ReadFull(tp, consumed)
	require.NoError(t, err)

	var client bytes.Buffer
	_, err = client.Write(tp.take())
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(&client, tp.rest())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}

	require.Equal(t, len(payload), client.Len(),
		"every byte the upstream sent must reach the client, including what the tap buffered")
	require.Equal(t, payload, client.Bytes())
}
