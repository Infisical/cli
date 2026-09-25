package cmd

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + enc(claims) + ".sig"
}

func TestJwtExpiryReadsExp(t *testing.T) {
	want := time.Now().Add(2 * time.Hour).Unix()
	exp, ok := jwtExpiry(makeJWT(t, map[string]any{"exp": want}))
	if !ok {
		t.Fatal("expected exp to be readable")
	}
	if exp.Unix() != want {
		t.Fatalf("exp = %d, want %d", exp.Unix(), want)
	}
}

func TestJwtExpiryRejectsNonJWT(t *testing.T) {
	for _, tok := range []string{
		"st.abc.def.ghi",             // service token (not a JWT)
		"not-a-jwt",                  // no dots
		"a.b",                        // too few segments
		makeJWT(t, map[string]any{}), // JWT without an exp claim
	} {
		if _, ok := jwtExpiry(tok); ok {
			t.Errorf("expected %q to have no readable expiry", tok)
		}
	}
}
