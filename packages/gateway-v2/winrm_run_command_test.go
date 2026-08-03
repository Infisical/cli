package gatewayv2

import (
	"testing"
	"time"
)

func TestResolveWinrmCommandTimeout(t *testing.T) {
	cases := []struct {
		name      string
		timeoutMs int
		want      time.Duration
	}{
		{"unset falls back to the default", 0, defaultWinrmCommandTimeout},
		{"negative falls back to the default", -1, defaultWinrmCommandTimeout},
		{"a value inside the range is honoured", 45_000, 45 * time.Second},
		{"the ceiling itself is honoured", int(maxWinrmCommandTimeout / time.Millisecond), maxWinrmCommandTimeout},
		{"above the ceiling clamps down to it", 600_000, maxWinrmCommandTimeout},
		{"a value large enough to overflow a Duration still clamps", 9_300_000_000_000, maxWinrmCommandTimeout},
	}

	for _, c := range cases {
		if got := resolveWinrmCommandTimeout(c.timeoutMs); got != c.want {
			t.Errorf("%s: resolveWinrmCommandTimeout(%d) = %s, want %s", c.name, c.timeoutMs, got, c.want)
		}
	}
}

func TestWinrmCommandBoundsAreConsistent(t *testing.T) {
	if defaultWinrmCommandTimeout > maxWinrmCommandTimeout {
		t.Fatal("the default timeout must fit inside the ceiling")
	}
	// The op deadline must be longer than the longest command, otherwise the envelope times out first.
	if maxWinrmCommandTimeout >= winrmOpDeadline {
		t.Fatalf("maxWinrmCommandTimeout (%s) must stay under winrmOpDeadline (%s)",
			maxWinrmCommandTimeout, winrmOpDeadline)
	}
}
