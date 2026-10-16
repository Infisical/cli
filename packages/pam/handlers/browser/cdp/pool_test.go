package cdp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeLauncher struct {
	mu       sync.Mutex
	launched int
	stopped  int
}

func (f *fakeLauncher) Launch(ctx context.Context, opts LaunchOptions) (*Instance, error) {
	f.mu.Lock()
	f.launched++
	n := f.launched
	f.mu.Unlock()

	done := make(chan struct{})
	return &Instance{
		CDPURL: fmt.Sprintf("ws://fake/%d", n),
		done:   done,
		stop: func() {
			close(done)
			f.mu.Lock()
			f.stopped++
			f.mu.Unlock()
		},
	}, nil
}

func (f *fakeLauncher) counts() (launched, stopped int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.launched, f.stopped
}

// Refills run in the background; acquiring before one lands would cold-launch instead.
func acquireWarm(t *testing.T, pool *Pool) *Instance {
	t.Helper()
	require.Eventually(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return len(pool.warm) > 0
	}, time.Second, 10*time.Millisecond)
	instance, err := pool.Acquire(t.Context())
	require.NoError(t, err)
	return instance
}

func TestPoolHandsOutWarmBrowsersWithinCap(t *testing.T) {
	launcher := &fakeLauncher{}
	pool := NewPool(launcher, PoolConfig{MaxInstances: 2, Warm: 1})

	first := acquireWarm(t, pool)
	require.Equal(t, "ws://fake/1", first.CDPURL, "the first session should get the browser warmed up front")

	second := acquireWarm(t, pool)
	require.Equal(t, "ws://fake/2", second.CDPURL)

	_, err := pool.Acquire(t.Context())
	require.ErrorIs(t, err, ErrAtCapacity)

	first.Stop()
	third := acquireWarm(t, pool)
	require.Equal(t, "ws://fake/3", third.CDPURL)

	second.Stop()
	third.Stop()
	pool.Close()
	require.Eventually(t, func() bool {
		launched, stopped := launcher.counts()
		return launched == stopped
	}, time.Second, 10*time.Millisecond, "every browser the pool launched should be stopped")
}

func TestPoolStopsIdleWarmBrowser(t *testing.T) {
	launcher := &fakeLauncher{}
	pool := NewPool(launcher, PoolConfig{Warm: 1, WarmIdle: 50 * time.Millisecond})
	defer pool.Close()

	require.Eventually(t, func() bool {
		launched, stopped := launcher.counts()
		return launched == 1 && stopped == 1
	}, time.Second, 10*time.Millisecond)
}
