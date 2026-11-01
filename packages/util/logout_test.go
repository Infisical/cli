package util

import (
	"errors"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/models"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/zalando/go-keyring"
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

// writeProfiles saves a config holding the given profiles under a temporary
// home, so the test reads and writes its own config file.
func writeProfiles(t *testing.T, profiles ...models.Profile) {
	t.Helper()
	useTempHome(t)
	if err := WriteConfigFile(&models.ConfigFile{Profiles: profiles}); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func storedOrgSessions(t *testing.T, name string) []models.OrgSessionRef {
	t.Helper()
	configFile, err := GetMigratedConfigFile()
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	profile, found := FindProfile(configFile, name)
	if !found {
		t.Fatalf("profile %q missing from config", name)
	}
	return profile.OrgSessions
}

// After a logout the org-session tokens are gone from the keyring, so the
// config must stop listing them.
func TestPruneOrgSessionIndex(t *testing.T) {
	t.Run("drops the logged out profile's entries and leaves other profiles alone", func(t *testing.T) {
		keyring.MockInit()
		writeProfiles(t,
			models.Profile{Name: "acme", OrgSessions: []models.OrgSessionRef{{OrgID: "org-1"}, {OrgID: "org-2"}}},
			models.Profile{Name: "globex", OrgSessions: []models.OrgSessionRef{{OrgID: "org-3"}}},
		)
		// org-2 has no token, as after a logout that already removed it.
		if err := StoreOrgSessionToken("acme", "org-1", "token-1"); err != nil {
			t.Fatalf("store token: %v", err)
		}

		if err := PruneOrgSessionIndex([]string{"acme"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := storedOrgSessions(t, "acme"); len(got) != 0 {
			t.Fatalf("expected acme's org sessions to be cleared, got %+v", got)
		}
		if _, found := GetOrgSessionToken("acme", "org-1"); found {
			t.Fatal("expected acme's org-session token to be deleted")
		}
		if got := storedOrgSessions(t, "globex"); len(got) != 1 || got[0].OrgID != "org-3" {
			t.Fatalf("expected globex to keep its org session, got %+v", got)
		}
	})

	t.Run("keeps an entry whose token could not be deleted", func(t *testing.T) {
		keyring.MockInit()
		writeProfiles(t, models.Profile{Name: "acme", OrgSessions: []models.OrgSessionRef{{OrgID: "org-1"}}})
		keyring.MockInitWithError(errors.New("keyring locked"))
		t.Cleanup(keyring.MockInit)

		if err := PruneOrgSessionIndex([]string{"acme"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := storedOrgSessions(t, "acme"); len(got) != 1 || got[0].OrgID != "org-1" {
			t.Fatalf("expected the undeletable entry to stay listed, got %+v", got)
		}
	})

	t.Run("ignores a profile that does not exist", func(t *testing.T) {
		keyring.MockInit()
		writeProfiles(t, models.Profile{Name: "acme"})

		if err := PruneOrgSessionIndex([]string{"missing"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
