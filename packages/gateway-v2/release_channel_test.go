package gatewayv2

import (
	"sync"
	"testing"
)

func TestReleaseChannelDecrements(t *testing.T) {
	g := &Gateway{}
	g.activeChannels.Add(3)
	g.releaseChannel(g.channelGeneration.Load())
	if got := g.activeChannels.Load(); got != 2 {
		t.Fatalf("count is %d, want 2", got)
	}
}

func TestReleaseChannelIgnoresPreviousGeneration(t *testing.T) {
	g := &Gateway{}
	stale := g.channelGeneration.Load()
	g.activeChannels.Add(2)

	// A relay reconnect: generation bumps and the count resets.
	g.channelGeneration.Add(1)
	g.activeChannels.Store(0)
	g.activeChannels.Add(1)

	g.releaseChannel(stale)
	g.releaseChannel(stale)

	if got := g.activeChannels.Load(); got != 1 {
		t.Fatalf("stale releases changed the count to %d, want 1", got)
	}
}

func TestReleaseChannelNeverGoesNegative(t *testing.T) {
	g := &Gateway{}
	generation := g.channelGeneration.Load()
	g.activeChannels.Add(2)
	g.activeChannels.Store(0)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.releaseChannel(generation)
		}()
	}
	wg.Wait()

	if got := g.activeChannels.Load(); got != 0 {
		t.Fatalf("count went to %d, want 0", got)
	}
}
