package pam

import (
	"testing"
)

func TestCompilePolicyPatterns(t *testing.T) {
	t.Run("nil config returns nil", func(t *testing.T) {
		result := compilePolicyPatterns(nil, "sess-1", "test")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("empty patterns returns nil", func(t *testing.T) {
		result := compilePolicyPatterns([]string{}, "sess-1", "test")
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid patterns all compile", func(t *testing.T) {
		result := compilePolicyPatterns([]string{`rm\s+-rf`, `shutdown`, `password\s*=\s*\S+`}, "sess-1", "test")
		if len(result) != 3 {
			t.Errorf("expected 3 compiled patterns, got %d", len(result))
		}
	})

	t.Run("invalid pattern is skipped", func(t *testing.T) {
		result := compilePolicyPatterns([]string{`rm\s+-rf`, `[invalid`, `shutdown`}, "sess-1", "test")
		if len(result) != 2 {
			t.Errorf("expected 2 compiled patterns (1 skipped), got %d", len(result))
		}
	})

	t.Run("all invalid patterns returns empty slice", func(t *testing.T) {
		result := compilePolicyPatterns([]string{`[bad`, `(unclosed`}, "sess-1", "test")
		if len(result) != 0 {
			t.Errorf("expected 0 compiled patterns, got %d", len(result))
		}
	})
}
