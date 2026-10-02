package clickhouse

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type recordingCloser struct{ closed atomic.Bool }

func (c *recordingCloser) Close() error {
	c.closed.Store(true)
	return nil
}

func TestIdleTimer(t *testing.T) {
	t.Run("a stalled read is cut off", func(t *testing.T) {
		var conn recordingCloser
		newIdleTimer(20*time.Millisecond, &conn).reset()
		require.Eventually(t, conn.closed.Load, time.Second, 5*time.Millisecond)
	})

	t.Run("arriving bytes keep it open", func(t *testing.T) {
		var conn recordingCloser
		g := newIdleTimer(60*time.Millisecond, &conn)
		for i := 0; i < 8; i++ {
			g.reset()
			time.Sleep(20 * time.Millisecond)
		}
		require.False(t, conn.closed.Load(), "a timer reset inside its window must not expire")
		require.Eventually(t, conn.closed.Load, time.Second, 5*time.Millisecond)
	})

	// Stop cannot call back an expiry already under way, so these drive one directly.
	t.Run("an expiry that lost its packet closes nothing", func(t *testing.T) {
		var conn recordingCloser
		g := newIdleTimer(time.Minute, &conn)
		g.reset()
		g.stop()
		g.reset()
		g.expire()
		require.False(t, conn.closed.Load(), "an expiry left by a finished packet must not close a later one")
	})

	t.Run("an expiry with no packet closes nothing", func(t *testing.T) {
		var conn recordingCloser
		g := newIdleTimer(time.Minute, &conn)
		g.reset()
		g.stop()
		g.expire()
		require.False(t, conn.closed.Load(), "a stopped timer must close nothing")
	})
}
