package masking

import (
	"regexp"
	"testing"
)

func TestCardNumbersNeedAValidChecksum(t *testing.T) {
	masker := NewMatcherMasker([]Matcher{CardNumbers()})
	for input, want := range map[string]string{
		"card 4111 1111 1111 1111":  "card [MASKED]",
		"card 4111-1111-1111-1111":  "card [MASKED]",
		"amex 3782 822463 10005":    "amex [MASKED]",
		"order 4111111111111112":    "order 4111111111111112",
		"order 1234 5678 9012 3456": "order 1234 5678 9012 3456",
	} {
		if got := masker.MaskString(input); got != want {
			t.Errorf("MaskString(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMatcherMaskerMergesOverlappingMatches(t *testing.T) {
	masker := NewMatcherMasker([]Matcher{
		regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]*:\S*@`),
		regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	})
	if got := masker.MaskString("postgres://svc:hunter2@10.0.4.12:5432/app"); got != "[MASKED]:5432/app" {
		t.Fatalf("got %q", got)
	}
}
