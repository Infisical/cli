package util

import (
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// testSigningKey is a dummy key used only to produce validly-formatted JWTs for tests.
var testSigningKey = []byte("test-secret-key")

func createToken(t *testing.T, exp *time.Time) string {
	t.Helper()
	claims := jwt.RegisteredClaims{}
	if exp != nil {
		claims.ExpiresAt = jwt.NewNumericDate(*exp)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(testSigningKey)
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return signed
}

func TestIsJWTExpired_ValidFutureToken(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour)
	token := createToken(t, &exp)
	if IsJWTExpired(token) {
		t.Error("expected token with future exp to not be expired")
	}
}

func TestIsJWTExpired_ExpiredToken(t *testing.T) {
	exp := time.Now().Add(-1 * time.Hour)
	token := createToken(t, &exp)
	if !IsJWTExpired(token) {
		t.Error("expected token with past exp to be expired")
	}
}

func TestIsJWTExpired_WithinBuffer(t *testing.T) {
	// 20 seconds from now — within the 30-second buffer
	exp := time.Now().Add(20 * time.Second)
	token := createToken(t, &exp)
	if !IsJWTExpired(token) {
		t.Error("expected token expiring within 30s buffer to be treated as expired")
	}
}

func TestIsJWTExpired_JustOutsideBuffer(t *testing.T) {
	// 31 seconds from now — outside the 30-second buffer
	exp := time.Now().Add(31 * time.Second)
	token := createToken(t, &exp)
	if IsJWTExpired(token) {
		t.Error("expected token expiring in 31s to not be treated as expired")
	}
}

func TestIsJWTExpired_EmptyString(t *testing.T) {
	if !IsJWTExpired("") {
		t.Error("expected empty string to be treated as expired")
	}
}

func TestIsJWTExpired_MalformedJWT(t *testing.T) {
	if !IsJWTExpired("not-a-jwt") {
		t.Error("expected malformed JWT to be treated as expired")
	}
}

func TestIsJWTExpired_InvalidBase64Payload(t *testing.T) {
	// Three parts but invalid base64 in payload
	if !IsJWTExpired("header.!!!invalid-base64!!!.signature") {
		t.Error("expected invalid base64 payload to be treated as expired")
	}
}

func TestIsJWTExpired_MissingExpClaim(t *testing.T) {
	token := createToken(t, nil)
	if !IsJWTExpired(token) {
		t.Error("expected token without exp claim to be treated as expired")
	}
}

// An organization token is minted from the profile's own session and dies with
// it. Sending one that outlived its session fails mid-command with no way to
// recover, so it must be treated as a cache miss and exchanged again.
func TestOrgSessionUsable(t *testing.T) {
	session := sessionToken(t, "session-a", time.Hour)
	sameSession := sessionToken(t, "session-a", time.Hour)
	otherSession := sessionToken(t, "session-b", time.Hour)
	expired := sessionToken(t, "session-a", -time.Hour)

	t.Run("a token from the current session is used", func(t *testing.T) {
		if !orgSessionUsable(sameSession, session) {
			t.Fatal("expected a cached token from the live session to be usable")
		}
	})

	t.Run("a token from a superseded session is not", func(t *testing.T) {
		if orgSessionUsable(otherSession, session) {
			t.Fatal("expected a token from another session to be re-exchanged rather than sent")
		}
	})

	t.Run("an expired token is not", func(t *testing.T) {
		if orgSessionUsable(expired, session) {
			t.Fatal("expected an expired token to be re-exchanged")
		}
	})

	t.Run("an empty or unparsable token is not", func(t *testing.T) {
		if orgSessionUsable("", session) || orgSessionUsable("not-a-jwt", session) {
			t.Fatal("expected an unreadable cached token to be re-exchanged")
		}
	})

	t.Run("an unreadable session token refuses the cache", func(t *testing.T) {
		// Without a session to compare against, nothing shows the cached token
		// is still live, so pay for an exchange rather than risk a failure.
		if orgSessionUsable(sameSession, "not-a-jwt") {
			t.Fatal("expected an unknown session to refuse the cached token")
		}
	})
}
