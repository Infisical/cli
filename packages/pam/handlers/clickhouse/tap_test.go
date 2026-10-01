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

func TestTapStopsHoldingBytesNothingWillRead(t *testing.T) {
	tp := newTap(bytes.NewReader(bytes.Repeat([]byte("x"), 64)))
	out := make([]byte, 1)

	_, err := io.ReadFull(tp, out)
	require.NoError(t, err)
	require.Len(t, tp.buf, 1)

	tp.stopHolding()
	_, err = io.ReadFull(tp, make([]byte, 32))
	require.NoError(t, err)
	require.Empty(t, tp.buf, "a tap told to stop must keep nothing")

	tp.hold()
	_, err = io.ReadFull(tp, out)
	require.NoError(t, err)
	require.Len(t, tp.buf, 1, "the next packet is held again")
}

func TestTapLosesNothingWhenAChargeIsRefused(t *testing.T) {
	tp := newTap(bytes.NewReader([]byte("abc")))
	tp.charge = func(int) error { return errGatewayFull }

	_, err := tp.Read(make([]byte, 1))
	require.ErrorIs(t, err, errGatewayFull)
	require.Empty(t, tp.buf)

	rest, err := io.ReadAll(tp.rest())
	require.NoError(t, err)
	require.Equal(t, "abc", string(rest), "a refused charge must not swallow a byte the relay still owes")
}
