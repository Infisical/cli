package cmd

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
)

func TestFormatExpiry(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name       string
		expiresAt  time.Time
		wantPrefix string
		wantExact  string
	}{
		{
			name:      "already expired",
			expiresAt: now.Add(-1 * time.Minute),
			wantExact: "expired",
		},
		{
			name:      "exactly at now is expired",
			expiresAt: now,
			wantExact: "expired",
		},
		{
			name:       "minutes only",
			expiresAt:  now.Add(15 * time.Minute),
			wantPrefix: "in ",
		},
		{
			name:       "hours and minutes",
			expiresAt:  now.Add(5*time.Hour + 30*time.Minute),
			wantPrefix: "in 5h ",
		},
		{
			name:       "days and hours",
			expiresAt:  now.Add(50 * time.Hour),
			wantPrefix: "in 2d ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatExpiry(tc.expiresAt)
			if tc.wantExact != "" {
				if got != tc.wantExact {
					t.Errorf("formatExpiry(%v) = %q, want %q", tc.expiresAt, got, tc.wantExact)
				}
				return
			}
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("formatExpiry(%v) = %q, want prefix %q", tc.expiresAt, got, tc.wantPrefix)
			}
		})
	}
}

func TestParseLoginJWTClaims(t *testing.T) {
	t.Run("happy path with org and sub-org", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		token := makeUnsignedJWT(t, map[string]any{
			"organizationId":    "org-1",
			"subOrganizationId": "sub-1",
			"exp":               exp,
		})

		claims, err := parseLoginJWTClaims(token)
		if err != nil {
			t.Fatalf("parseLoginJWTClaims: unexpected error: %v", err)
		}
		if claims.OrganizationID != "org-1" {
			t.Errorf("OrganizationID = %q, want %q", claims.OrganizationID, "org-1")
		}
		if claims.SubOrganizationID != "sub-1" {
			t.Errorf("SubOrganizationID = %q, want %q", claims.SubOrganizationID, "sub-1")
		}
		if claims.ExpiresAt == nil || claims.ExpiresAt.Unix() != exp {
			t.Errorf("ExpiresAt = %v, want unix %d", claims.ExpiresAt, exp)
		}
	})

	t.Run("machine identity claims parse", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		token := makeUnsignedJWT(t, map[string]any{
			"identityId":   "id-123",
			"identityName": "my-ci-bot",
			"authMethod":   "universal-auth",
			"orgId":        "org-1",
			"exp":          exp,
		})

		claims, err := parseLoginJWTClaims(token)
		if err != nil {
			t.Fatalf("parseLoginJWTClaims: unexpected error: %v", err)
		}
		if claims.IdentityID != "id-123" {
			t.Errorf("IdentityID = %q, want %q", claims.IdentityID, "id-123")
		}
		if claims.IdentityName != "my-ci-bot" {
			t.Errorf("IdentityName = %q, want %q", claims.IdentityName, "my-ci-bot")
		}
		if claims.AuthMethod != "universal-auth" {
			t.Errorf("AuthMethod = %q, want %q", claims.AuthMethod, "universal-auth")
		}
		if claims.OrgID != "org-1" {
			t.Errorf("OrgID = %q, want %q", claims.OrgID, "org-1")
		}
	})

	t.Run("token without organization claims still parses", func(t *testing.T) {
		token := makeUnsignedJWT(t, map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		claims, err := parseLoginJWTClaims(token)
		if err != nil {
			t.Fatalf("parseLoginJWTClaims: unexpected error: %v", err)
		}
		if claims.OrganizationID != "" {
			t.Errorf("OrganizationID = %q, want empty", claims.OrganizationID)
		}
		if claims.SubOrganizationID != "" {
			t.Errorf("SubOrganizationID = %q, want empty", claims.SubOrganizationID)
		}
	})

	t.Run("malformed token returns error", func(t *testing.T) {
		if _, err := parseLoginJWTClaims("not-a-jwt"); err == nil {
			t.Errorf("parseLoginJWTClaims(%q) = nil error, want error", "not-a-jwt")
		}
	})

	t.Run("non-base64 payload returns error", func(t *testing.T) {
		if _, err := parseLoginJWTClaims("aaa.!!!.ccc"); err == nil {
			t.Errorf("parseLoginJWTClaims with bad payload = nil error, want error")
		}
	})
}

func TestDetectMachineIdentityEnvToken(t *testing.T) {
	t.Run("no env vars set", func(t *testing.T) {
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "")
		t.Setenv(util.INFISICAL_TOKEN_NAME, "")

		if _, _, ok := detectMachineIdentityEnvToken(); ok {
			t.Errorf("detectMachineIdentityEnvToken() = ok, want !ok when no env vars set")
		}
	})

	t.Run("universal-auth access token takes precedence", func(t *testing.T) {
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "ua-token")
		t.Setenv(util.INFISICAL_TOKEN_NAME, "should-be-ignored")

		token, source, ok := detectMachineIdentityEnvToken()
		if !ok {
			t.Fatalf("detectMachineIdentityEnvToken() = !ok, want ok")
		}
		if token != "ua-token" {
			t.Errorf("token = %q, want %q", token, "ua-token")
		}
		if !strings.Contains(source, util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME) {
			t.Errorf("source = %q, want it to contain %q", source, util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME)
		}
	})

	t.Run("falls back to INFISICAL_TOKEN", func(t *testing.T) {
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "")
		t.Setenv(util.INFISICAL_TOKEN_NAME, "st.abc.def")

		token, source, ok := detectMachineIdentityEnvToken()
		if !ok {
			t.Fatalf("detectMachineIdentityEnvToken() = !ok, want ok")
		}
		if token != "st.abc.def" {
			t.Errorf("token = %q, want %q", token, "st.abc.def")
		}
		if !strings.Contains(source, util.INFISICAL_TOKEN_NAME) {
			t.Errorf("source = %q, want it to contain %q", source, util.INFISICAL_TOKEN_NAME)
		}
	})

	t.Run("whitespace-only env value is ignored", func(t *testing.T) {
		t.Setenv(util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME, "   ")
		t.Setenv(util.INFISICAL_TOKEN_NAME, "")

		if _, _, ok := detectMachineIdentityEnvToken(); ok {
			t.Errorf("detectMachineIdentityEnvToken() = ok for whitespace-only value, want !ok")
		}
	})
}

func makeUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	headerJSON, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(payloadJSON) + "."
}
