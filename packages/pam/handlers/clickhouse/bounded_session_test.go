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

func TestStallGuard(t *testing.T) {
	t.Run("a stalled read is cut off", func(t *testing.T) {
		var conn recordingCloser
		newStallGuard(20*time.Millisecond, &conn).arm()
		require.Eventually(t, conn.closed.Load, time.Second, 5*time.Millisecond)
	})

	t.Run("arriving bytes keep it open", func(t *testing.T) {
		var conn recordingCloser
		g := newStallGuard(60*time.Millisecond, &conn)
		for i := 0; i < 8; i++ {
			g.arm()
			time.Sleep(20 * time.Millisecond)
		}
		require.False(t, conn.closed.Load(), "a guard refreshed inside its window must not fire")
		require.Eventually(t, conn.closed.Load, time.Second, 5*time.Millisecond)
	})

	// Stop cannot call back a firing already under way, so these drive one directly.
	t.Run("a firing that lost its packet closes nothing", func(t *testing.T) {
		var conn recordingCloser
		g := newStallGuard(time.Minute, &conn)
		g.arm()
		g.disarm()
		g.arm()
		g.fire()
		require.False(t, conn.closed.Load(), "a firing from a finished packet must not close a later one")
	})

	t.Run("a firing with no packet closes nothing", func(t *testing.T) {
		var conn recordingCloser
		g := newStallGuard(time.Minute, &conn)
		g.arm()
		g.disarm()
		g.fire()
		require.False(t, conn.closed.Load(), "a disarmed guard must close nothing")
	})
}
