package util

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
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

func TestIsOrganizationScopeError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "403 api error",
			err: &api.APIError{
				StatusCode: 403,
			},
			want: true,
		},
		{
			name: "404 api error",
			err: &api.APIError{
				StatusCode: 404,
			},
			want: false,
		},
		{
			name: "plain error",
			err:  errors.New("boom"),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isOrganizationScopeError(tc.err)
			if got != tc.want {
				t.Errorf("isOrganizationScopeError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestWriteWorkspaceConfigToPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".infisical.json")
	workspaceConfig := models.WorkspaceConfigFile{
		WorkspaceId:        "workspace-123",
		OrganizationId:     "org-123",
		DefaultEnvironment: "dev",
		GitBranchToEnvironmentMapping: map[string]string{
			"main": "prod",
		},
		Domain: "https://example.infisical.com",
	}

	err := WriteWorkspaceConfigToPath(workspaceConfig, path)
	if err != nil {
		t.Fatalf("WriteWorkspaceConfigToPath: unexpected error: %v", err)
	}

	storedConfig, err := GetWorkspaceConfigByPath(path)
	if err != nil {
		t.Fatalf("GetWorkspaceConfigByPath: unexpected error: %v", err)
	}
	if storedConfig.WorkspaceId != workspaceConfig.WorkspaceId {
		t.Errorf("WorkspaceId = %q, want %q", storedConfig.WorkspaceId, workspaceConfig.WorkspaceId)
	}
	if storedConfig.OrganizationId != workspaceConfig.OrganizationId {
		t.Errorf("OrganizationId = %q, want %q", storedConfig.OrganizationId, workspaceConfig.OrganizationId)
	}
	if storedConfig.DefaultEnvironment != workspaceConfig.DefaultEnvironment {
		t.Errorf("DefaultEnvironment = %q, want %q", storedConfig.DefaultEnvironment, workspaceConfig.DefaultEnvironment)
	}
	if storedConfig.Domain != workspaceConfig.Domain {
		t.Errorf("Domain = %q, want %q", storedConfig.Domain, workspaceConfig.Domain)
	}
	if storedConfig.GitBranchToEnvironmentMapping["main"] != workspaceConfig.GitBranchToEnvironmentMapping["main"] {
		t.Errorf("GitBranchToEnvironmentMapping[main] = %q, want %q", storedConfig.GitBranchToEnvironmentMapping["main"], workspaceConfig.GitBranchToEnvironmentMapping["main"])
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
