package util

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
			name: "403 org scoping error",
			err: &api.APIError{
				StatusCode:   403,
				ErrorMessage: "This project does not belong to your selected organization",
			},
			want: true,
		},
		{
			name: "403 generic permission error",
			err: &api.APIError{
				StatusCode:   403,
				ErrorMessage: "You don't have access to this project",
			},
			want: false,
		},
		{
			name: "404 api error",
			err: &api.APIError{
				StatusCode:   404,
				ErrorMessage: "This project does not belong to your selected organization",
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
	workspaceConfig := models.WorkspaceConfigFile{
		WorkspaceId:        "workspace-123",
		OrganizationId:     "org-123",
		DefaultEnvironment: "dev",
		GitBranchToEnvironmentMapping: map[string]string{
			"main": "prod",
		},
		Domain: "https://example.infisical.com",
	}

	assertStoredConfig := func(t *testing.T, path string) {
		t.Helper()

		rawConfig, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s): unexpected error: %v", path, err)
		}
		if !strings.Contains(string(rawConfig), "organization-id: org-123") {
			t.Errorf("expected yaml to contain organization-id, got:\n%s", rawConfig)
		}

		storedConfig, err := GetWorkSpaceFromFilePath(filepath.Dir(path))
		if err != nil {
			t.Fatalf("GetWorkSpaceFromFilePath: unexpected error: %v", err)
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

	t.Run("yaml path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".infisical.yaml")

		if err := WriteWorkspaceConfigToPath(workspaceConfig, path); err != nil {
			t.Fatalf("WriteWorkspaceConfigToPath: unexpected error: %v", err)
		}

		assertStoredConfig(t, path)
	})

	t.Run("legacy json path writes yaml alongside", func(t *testing.T) {
		dir := t.TempDir()
		legacyPath := filepath.Join(dir, ".infisical.json")

		if err := WriteWorkspaceConfigToPath(workspaceConfig, legacyPath); err != nil {
			t.Fatalf("WriteWorkspaceConfigToPath: unexpected error: %v", err)
		}

		if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
			t.Errorf("expected no .infisical.json to be written, stat err = %v", err)
		}
		assertStoredConfig(t, filepath.Join(dir, ".infisical.yaml"))
	})
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
