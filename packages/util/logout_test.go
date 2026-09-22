package util

import (
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// sessionToken builds a session JWT carrying a session id and an expiry, which
// is what the retention logic reads.
func sessionToken(t *testing.T, sessionID string, expiresIn time.Duration) string {
	t.Helper()

	claims := userTokenOrgClaims{
		TokenVersionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(testSigningKey)
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return signed
}

// A session is only worth keeping alive for a profile that can still use it.
// Retaining one named by an expired token would skip revoking a session the
// user asked to end, while the profile holding that token re-logins anyway.
func TestCollectLiveSessionIDs(t *testing.T) {
	live := sessionToken(t, "session-live", time.Hour)
	expired := sessionToken(t, "session-expired", -time.Hour)

	t.Run("an unexpired token keeps its session", func(t *testing.T) {
		got := collectLiveSessionIDs([]string{live})
		if len(got) != 1 || got[0] != "session-live" {
			t.Fatalf("expected [session-live], got %v", got)
		}
	})

	t.Run("an expired token does not", func(t *testing.T) {
		if got := collectLiveSessionIDs([]string{expired}); len(got) != 0 {
			t.Fatalf("expected no retained sessions, got %v", got)
		}
	})

	t.Run("a mix keeps only the live one", func(t *testing.T) {
		got := collectLiveSessionIDs([]string{expired, live})
		if len(got) != 1 || got[0] != "session-live" {
			t.Fatalf("expected only the live session, got %v", got)
		}
	})

	t.Run("empty and unparsable tokens are ignored", func(t *testing.T) {
		if got := collectLiveSessionIDs([]string{"", "not-a-jwt"}); len(got) != 0 {
			t.Fatalf("expected no retained sessions, got %v", got)
		}
	})

	// collectSessionIDs still reports every session the profile references, so
	// the profile being logged out revokes its own expired sessions too.
	t.Run("the unfiltered collector still sees expired sessions", func(t *testing.T) {
		got := collectSessionIDs([]string{expired})
		if len(got) != 1 || got[0] != "session-expired" {
			t.Fatalf("expected the expired session to still be collected, got %v", got)
		}
	})
}
