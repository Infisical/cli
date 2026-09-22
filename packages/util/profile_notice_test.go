package util

import "testing"

func TestFormatProfileNotice(t *testing.T) {
	t.Run("the default profile with no override is quiet", func(t *testing.T) {
		got := FormatProfileNotice(ResolvedProfile{Name: "a@x.com", Source: ProfileSourceDefault}, LoggedInUserDetails{OrganizationName: "Acme", OrganizationSource: OrgSourceProfileDefault})
		if got != "" {
			t.Fatalf("expected no notice, got %q", got)
		}
	})

	t.Run("a pinned profile names the source and organization", func(t *testing.T) {
		got := FormatProfileNotice(ResolvedProfile{Name: "work", Source: ProfileSourceEnv}, LoggedInUserDetails{OrganizationName: "Acme", OrganizationSource: OrgSourceProfileDefault})
		if got != "Using profile 'work' (org Acme) via INFISICAL_PROFILE environment variable" {
			t.Fatalf("unexpected notice %q", got)
		}
	})

	t.Run("a directory binding includes the directory", func(t *testing.T) {
		got := FormatProfileNotice(ResolvedProfile{Name: "work", Source: ProfileSourceDirectory, ScopeDir: "/repo"}, LoggedInUserDetails{OrganizationID: "org-1", OrganizationSource: OrgSourceProfileDefault})
		if got != "Using profile 'work' (org org-1) via directory scope /repo" {
			t.Fatalf("unexpected notice %q", got)
		}
	})

	t.Run("an org override on the default profile reports the override", func(t *testing.T) {
		got := FormatProfileNotice(ResolvedProfile{Name: "a@x.com", Source: ProfileSourceDefault}, LoggedInUserDetails{OrganizationName: "Globex", OrganizationSource: OrgSourceFlag})
		if got != "Using profile 'a@x.com' (org Globex) via --org flag" {
			t.Fatalf("unexpected notice %q", got)
		}
	})

	t.Run("an org override on a pinned profile reports both", func(t *testing.T) {
		got := FormatProfileNotice(ResolvedProfile{Name: "work", Source: ProfileSourceFlag, ShadowedName: "client-a"}, LoggedInUserDetails{OrganizationName: "Globex", OrganizationSource: OrgSourceEnv})
		want := "Using profile 'work' (org Globex) via --profile flag, org via INFISICAL_ORG environment variable, overriding this directory's binding to 'client-a'"
		if got != want {
			t.Fatalf("unexpected notice %q", got)
		}
	})
}
