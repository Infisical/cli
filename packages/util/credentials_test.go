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
