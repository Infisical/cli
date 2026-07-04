package util

import (
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/models"
	jwt "github.com/golang-jwt/jwt/v5"
)

func TestGetTokenOrganizationId(t *testing.T) {
	t.Run("decodes organizationId claim", func(t *testing.T) {
		token := makeUnsignedJWT(t, map[string]any{
			"organizationId": "org-123",
			"exp":            time.Now().Add(time.Hour).Unix(),
		})

		organizationId, err := getTokenOrganizationId(token)
		if err != nil {
			t.Fatalf("getTokenOrganizationId: unexpected error: %v", err)
		}
		if organizationId != "org-123" {
			t.Errorf("organizationId = %q, want %q", organizationId, "org-123")
		}
	})

	t.Run("malformed token returns error", func(t *testing.T) {
		if _, err := getTokenOrganizationId("not-a-jwt"); err == nil {
			t.Errorf("getTokenOrganizationId(%q) = nil error, want error", "not-a-jwt")
		}
	})
}

func TestResolveOrgScopedToken(t *testing.T) {
	storedToken := makeUnsignedJWT(t, map[string]any{
		"organizationId": "org-current",
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	loggedInUserDetails := LoggedInUserDetails{
		UserCredentials: models.UserCredentials{
			JTWToken: storedToken,
		},
	}

	t.Run("returns stored token when no org source is set", func(t *testing.T) {
		t.Setenv("INFISICAL_ORGANIZATION_ID", "")

		resolvedToken, err := resolveOrgScopedToken(loggedInUserDetails, "", "")
		if err != nil {
			t.Fatalf("resolveOrgScopedToken: unexpected error: %v", err)
		}
		if resolvedToken != storedToken {
			t.Errorf("resolvedToken = %q, want stored token %q", resolvedToken, storedToken)
		}
	})

	cases := []struct {
		name               string
		flagOrganization   string
		envOrganization    string
		configOrganization string
	}{
		{
			name:               "matching flag org returns stored token",
			flagOrganization:   "org-current",
			envOrganization:    "org-env",
			configOrganization: "org-config",
		},
		{
			name:               "matching env org returns stored token when flag empty",
			flagOrganization:   "",
			envOrganization:    "org-current",
			configOrganization: "org-config",
		},
		{
			name:               "matching config org returns stored token when flag and env empty",
			flagOrganization:   "",
			envOrganization:    "",
			configOrganization: "org-current",
		},
		{
			name:               "matching org returns stored token when all sources equal current",
			flagOrganization:   "org-current",
			envOrganization:    "org-current",
			configOrganization: "org-current",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("INFISICAL_ORGANIZATION_ID", tc.envOrganization)

			resolvedToken, err := resolveOrgScopedToken(loggedInUserDetails, tc.flagOrganization, tc.configOrganization)
			if err != nil {
				t.Fatalf("resolveOrgScopedToken: unexpected error: %v", err)
			}
			if resolvedToken != storedToken {
				t.Errorf("resolvedToken = %q, want stored token %q", resolvedToken, storedToken)
			}
		})
	}
}

func makeUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims))
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString: unexpected error: %v", err)
	}

	return tokenString
}
