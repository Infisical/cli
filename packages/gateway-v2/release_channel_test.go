package gatewayv2

import (
	"sync"
	"testing"
)

func TestReleaseChannelNeverGoesNegative(t *testing.T) {
	g := &Gateway{}
	g.activeChannels.Add(1)
	g.activeChannels.Add(1)

	// Reset with handlers still in flight, as on a relay reconnect.
	g.activeChannels.Store(0)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.releaseChannel()
		}()
	}
	wg.Wait()

	if got := g.activeChannels.Load(); got != 0 {
		t.Fatalf("count went to %d, want 0", got)
	}
}

func TestReleaseChannelDecrements(t *testing.T) {
	g := &Gateway{}
	g.activeChannels.Add(3)
	g.releaseChannel()
	if got := g.activeChannels.Load(); got != 2 {
		t.Fatalf("count is %d, want 2", got)
	}
}
