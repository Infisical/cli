package util

import (
	"path/filepath"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
)

func TestMigrateConfigProfiles(t *testing.T) {
	t.Run("legacy single user becomes a profile named after the email", func(t *testing.T) {
		configFile := models.ConfigFile{
			LoggedInUserEmail:  "scott@example.com",
			LoggedInUserDomain: "https://app.infisical.com/api",
		}

		changed := MigrateConfigProfiles(&configFile)

		if !changed {
			t.Fatal("expected migration to report a change")
		}
		if len(configFile.Profiles) != 1 {
			t.Fatalf("expected 1 profile, got %d", len(configFile.Profiles))
		}
		profile := configFile.Profiles[0]
		if profile.Name != "scott@example.com" || profile.Email != "scott@example.com" || profile.Domain != "https://app.infisical.com/api" {
			t.Fatalf("unexpected migrated profile: %+v", profile)
		}
		if configFile.ActiveProfile != "scott@example.com" {
			t.Fatalf("expected active profile to be the migrated one, got %q", configFile.ActiveProfile)
		}
	})

	t.Run("legacy roster becomes profiles and the active pointer follows LoggedInUserEmail", func(t *testing.T) {
		configFile := models.ConfigFile{
			LoggedInUserEmail:  "b@example.com",
			LoggedInUserDomain: "https://eu.infisical.com/api",
			LoggedInUsers: []models.LoggedInUser{
				{Email: "a@example.com", Domain: "https://app.infisical.com/api"},
				{Email: "b@example.com", Domain: "https://eu.infisical.com/api"},
			},
		}

		MigrateConfigProfiles(&configFile)

		if len(configFile.Profiles) != 2 {
			t.Fatalf("expected 2 profiles, got %d", len(configFile.Profiles))
		}
		if configFile.ActiveProfile != "b@example.com" {
			t.Fatalf("expected active profile b@example.com, got %q", configFile.ActiveProfile)
		}
	})

	t.Run("is idempotent", func(t *testing.T) {
		configFile := models.ConfigFile{
			LoggedInUserEmail:  "scott@example.com",
			LoggedInUserDomain: "https://app.infisical.com/api",
		}

		MigrateConfigProfiles(&configFile)
		changed := MigrateConfigProfiles(&configFile)

		if changed {
			t.Fatal("expected second migration to be a no-op")
		}
		if len(configFile.Profiles) != 1 {
			t.Fatalf("expected 1 profile after re-migration, got %d", len(configFile.Profiles))
		}
	})

	t.Run("does nothing for an empty config", func(t *testing.T) {
		configFile := models.ConfigFile{}

		if MigrateConfigProfiles(&configFile) {
			t.Fatal("expected no change for an empty config")
		}
		if len(configFile.Profiles) != 0 || configFile.ActiveProfile != "" {
			t.Fatalf("expected empty config to stay empty, got %+v", configFile)
		}
	})

	t.Run("a legacy user switch (LoggedInUserEmail moved by an old binary) wins over a stale active pointer", func(t *testing.T) {
		configFile := models.ConfigFile{
			LoggedInUserEmail: "b@example.com",
			ActiveProfile:     "a@example.com",
			Profiles: []models.Profile{
				{Name: "a@example.com", Email: "a@example.com"},
				{Name: "b@example.com", Email: "b@example.com"},
			},
		}

		changed := MigrateConfigProfiles(&configFile)

		if !changed {
			t.Fatal("expected reconciliation to report a change")
		}
		if configFile.ActiveProfile != "b@example.com" {
			t.Fatalf("expected active profile b@example.com, got %q", configFile.ActiveProfile)
		}
	})

	t.Run("roster mirrors of named profiles do not spawn phantom profiles", func(t *testing.T) {
		// State after a targeted first login: only a named profile exists, and
		// the legacy fields mirror it for old-binary compatibility.
		configFile := models.ConfigFile{
			LoggedInUserEmail:  "scott@example.com",
			LoggedInUserDomain: "https://app.infisical.com/api",
			LoggedInUsers: []models.LoggedInUser{
				{Email: "scott@example.com", Domain: "https://app.infisical.com/api"},
			},
			ActiveProfile: "globex",
			Profiles: []models.Profile{
				{Name: "globex", Email: "scott@example.com", Domain: "https://app.infisical.com/api", OrganizationID: "org-2"},
			},
		}

		changed := MigrateConfigProfiles(&configFile)

		if changed {
			t.Fatal("expected migration to be a no-op")
		}
		if len(configFile.Profiles) != 1 {
			t.Fatalf("expected no phantom profile, got %+v", configFile.Profiles)
		}
		if configFile.ActiveProfile != "globex" {
			t.Fatalf("expected active profile to stay globex, got %q", configFile.ActiveProfile)
		}
	})

	t.Run("legacy switch reconciles to a named profile when no email-named one exists", func(t *testing.T) {
		configFile := models.ConfigFile{
			LoggedInUserEmail: "b@example.com",
			ActiveProfile:     "a-work",
			LoggedInUsers: []models.LoggedInUser{
				{Email: "a@example.com"},
				{Email: "b@example.com"},
			},
			Profiles: []models.Profile{
				{Name: "a-work", Email: "a@example.com"},
				{Name: "b-work", Email: "b@example.com"},
			},
		}

		MigrateConfigProfiles(&configFile)

		if len(configFile.Profiles) != 2 {
			t.Fatalf("expected no phantom profiles, got %+v", configFile.Profiles)
		}
		if configFile.ActiveProfile != "b-work" {
			t.Fatalf("expected active profile b-work, got %q", configFile.ActiveProfile)
		}
	})

	t.Run("a named active profile for the same account is kept", func(t *testing.T) {
		configFile := models.ConfigFile{
			LoggedInUserEmail: "scott@example.com",
			ActiveProfile:     "client-a",
			Profiles: []models.Profile{
				{Name: "client-a", Email: "scott@example.com", OrganizationID: "org-1"},
				{Name: "scott@example.com", Email: "scott@example.com"},
			},
		}

		MigrateConfigProfiles(&configFile)

		if configFile.ActiveProfile != "client-a" {
			t.Fatalf("expected active profile client-a to be kept, got %q", configFile.ActiveProfile)
		}
	})
}

func TestResolveProfileWith(t *testing.T) {
	scopedDir := filepath.Join("/", "home", "scott", "work", "client-a")

	configFile := models.ConfigFile{
		ActiveProfile: "default-profile",
		Profiles: []models.Profile{
			{Name: "default-profile", Email: "scott@example.com"},
			{Name: "client-a", Email: "scott@example.com"},
		},
		DirectoryProfiles: map[string]string{
			scopedDir: "client-a",
		},
	}

	t.Run("an override beats everything", func(t *testing.T) {
		resolved := resolveProfileWith(configFile, "client-b", ProfileSourceEnv, scopedDir)
		if resolved.Name != "client-b" || resolved.Source != ProfileSourceEnv {
			t.Fatalf("unexpected resolution: %+v", resolved)
		}
	})

	t.Run("a directory scope beats the global default", func(t *testing.T) {
		resolved := resolveProfileWith(configFile, "", "", scopedDir)
		if resolved.Name != "client-a" || resolved.Source != ProfileSourceDirectory || resolved.ScopeDir != scopedDir {
			t.Fatalf("unexpected resolution: %+v", resolved)
		}
	})

	t.Run("a subdirectory inherits the nearest ancestor binding", func(t *testing.T) {
		resolved := resolveProfileWith(configFile, "", "", filepath.Join(scopedDir, "api", "src"))
		if resolved.Name != "client-a" || resolved.ScopeDir != scopedDir {
			t.Fatalf("unexpected resolution: %+v", resolved)
		}
	})

	t.Run("a nested binding beats an ancestor binding", func(t *testing.T) {
		nested := filepath.Join(scopedDir, "sub-project")
		withNested := configFile
		withNested.DirectoryProfiles = map[string]string{
			scopedDir: "client-a",
			nested:    "client-b",
		}
		resolved := resolveProfileWith(withNested, "", "", filepath.Join(nested, "deep"))
		if resolved.Name != "client-b" || resolved.ScopeDir != nested {
			t.Fatalf("unexpected resolution: %+v", resolved)
		}
	})

	t.Run("an unbound directory falls back to the global default", func(t *testing.T) {
		resolved := resolveProfileWith(configFile, "", "", filepath.Join("/", "home", "scott", "other"))
		if resolved.Name != "default-profile" || resolved.Source != ProfileSourceDefault {
			t.Fatalf("unexpected resolution: %+v", resolved)
		}
	})

	t.Run("unmigrated legacy config falls back to LoggedInUserEmail", func(t *testing.T) {
		legacyOnly := models.ConfigFile{LoggedInUserEmail: "scott@example.com"}
		resolved := resolveProfileWith(legacyOnly, "", "", "")
		if resolved.Name != "scott@example.com" || resolved.Source != ProfileSourceDefault {
			t.Fatalf("unexpected resolution: %+v", resolved)
		}
	})

	t.Run("nothing resolves on a fresh machine", func(t *testing.T) {
		resolved := resolveProfileWith(models.ConfigFile{}, "", "", "")
		if resolved.Name != "" {
			t.Fatalf("expected empty resolution, got %+v", resolved)
		}
	})
}

func TestDeriveProfileName(t *testing.T) {
	base := models.ConfigFile{
		Profiles: []models.Profile{
			{Name: "scott@example.com", Email: "scott@example.com", Domain: "https://app.infisical.com/api", OrganizationID: "org-1"},
		},
	}

	t.Run("a new account uses the bare email", func(t *testing.T) {
		name := DeriveProfileName(base, "new@example.com", "https://app.infisical.com/api", "org-9", "Acme")
		if name != "new@example.com" {
			t.Fatalf("expected bare email, got %q", name)
		}
	})

	t.Run("a plus-addressed email is used verbatim", func(t *testing.T) {
		name := DeriveProfileName(base, "ci+tests@example.com", "https://app.infisical.com/api", "org-9", "Acme")
		if name != "ci+tests@example.com" {
			t.Fatalf("expected plus-addressed email verbatim, got %q", name)
		}
	})

	t.Run("relogin into the same account, instance, and org reuses the profile", func(t *testing.T) {
		name := DeriveProfileName(base, "scott@example.com", "https://app.infisical.com/api", "org-1", "Acme")
		if name != "scott@example.com" {
			t.Fatalf("expected existing profile name to be reused, got %q", name)
		}
	})

	t.Run("relogin reuses a named profile for the same account, instance, and org", func(t *testing.T) {
		configFile := models.ConfigFile{
			Profiles: []models.Profile{
				{Name: "client-a", Email: "scott@example.com", Domain: "https://app.infisical.com/api", OrganizationID: "org-1"},
			},
		}
		name := DeriveProfileName(configFile, "scott@example.com", "https://app.infisical.com/api", "org-1", "Acme")
		if name != "client-a" {
			t.Fatalf("expected named profile to be reused, got %q", name)
		}
	})

	t.Run("adopts a migrated profile whose org is unknown", func(t *testing.T) {
		configFile := models.ConfigFile{
			Profiles: []models.Profile{
				{Name: "scott@example.com", Email: "scott@example.com", Domain: "https://app.infisical.com/api"},
			},
		}
		name := DeriveProfileName(configFile, "scott@example.com", "https://app.infisical.com/api", "org-1", "Acme")
		if name != "scott@example.com" {
			t.Fatalf("expected migrated profile to be adopted, got %q", name)
		}
	})

	t.Run("a second organization gets a suffixed name instead of overwriting", func(t *testing.T) {
		name := DeriveProfileName(base, "scott@example.com", "https://app.infisical.com/api", "org-2", "Beta Corp")
		if name != "scott@example.com--beta-corp" {
			t.Fatalf("expected org-suffixed name, got %q", name)
		}
	})

	t.Run("falls back to the org id when the org name is unavailable", func(t *testing.T) {
		name := DeriveProfileName(base, "scott@example.com", "https://app.infisical.com/api", "1234567890ab", "")
		if name != "scott@example.com--12345678" {
			t.Fatalf("expected org-id-suffixed name, got %q", name)
		}
	})

	t.Run("numbers suffix collisions", func(t *testing.T) {
		configFile := models.ConfigFile{
			Profiles: []models.Profile{
				{Name: "scott@example.com", Email: "scott@example.com", Domain: "https://app.infisical.com/api", OrganizationID: "org-1"},
				{Name: "scott@example.com--beta", Email: "scott@example.com", Domain: "https://app.infisical.com/api", OrganizationID: "org-2"},
			},
		}
		name := DeriveProfileName(configFile, "scott@example.com", "https://app.infisical.com/api", "org-3", "Beta")
		if name != "scott@example.com--beta-2" {
			t.Fatalf("expected numbered suffix, got %q", name)
		}
	})
}

func TestSetActiveProfileSyncsLegacyFields(t *testing.T) {
	t.Run("an email-named profile publishes the legacy pointer", func(t *testing.T) {
		configFile := models.ConfigFile{
			Profiles: []models.Profile{
				{Name: "scott@example.com", Email: "scott@example.com", Domain: "https://eu.infisical.com/api"},
			},
		}

		if err := SetActiveProfile(&configFile, "scott@example.com"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if configFile.LoggedInUserEmail != "scott@example.com" || configFile.LoggedInUserDomain != "https://eu.infisical.com/api" {
			t.Fatalf("legacy fields not synced: %+v", configFile)
		}
		if len(configFile.LoggedInUsers) != 1 || configFile.LoggedInUsers[0].Email != "scott@example.com" {
			t.Fatalf("legacy roster not synced: %+v", configFile.LoggedInUsers)
		}
	})

	t.Run("a named profile clears it, so an old binary cannot load another profile's token", func(t *testing.T) {
		configFile := models.ConfigFile{
			LoggedInUserEmail:  "scott@example.com",
			LoggedInUserDomain: "https://app.infisical.com/api",
			Profiles: []models.Profile{
				{Name: "client-a", Email: "scott@example.com", Domain: "https://eu.infisical.com/api"},
			},
		}

		if err := SetActiveProfile(&configFile, "client-a"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if configFile.ActiveProfile != "client-a" {
			t.Fatalf("expected active profile client-a, got %q", configFile.ActiveProfile)
		}
		if configFile.LoggedInUserEmail != "" || configFile.LoggedInUserDomain != "" {
			t.Fatalf("expected the legacy pointer to be cleared, got %+v", configFile)
		}
	})

	t.Run("a missing profile errors", func(t *testing.T) {
		configFile := models.ConfigFile{Profiles: []models.Profile{{Name: "a", Email: "a"}}}
		if err := SetActiveProfile(&configFile, "missing"); err == nil {
			t.Fatal("expected an error for a missing profile")
		}
	})
}

func TestRemoveProfile(t *testing.T) {
	scopedDir := filepath.Join("/", "home", "scott", "work", "client-a")
	configFile := models.ConfigFile{
		ActiveProfile:      "client-a",
		LoggedInUserEmail:  "scott@example.com",
		LoggedInUserDomain: "https://app.infisical.com/api",
		LoggedInUsers: []models.LoggedInUser{
			{Email: "scott@example.com", Domain: "https://app.infisical.com/api"},
			{Email: "other@example.com", Domain: "https://app.infisical.com/api"},
		},
		Profiles: []models.Profile{
			{Name: "client-a", Email: "scott@example.com", Domain: "https://app.infisical.com/api"},
			{Name: "other@example.com", Email: "other@example.com", Domain: "https://app.infisical.com/api"},
		},
		DirectoryProfiles: map[string]string{
			scopedDir: "client-a",
		},
	}

	if !RemoveProfile(&configFile, "client-a") {
		t.Fatal("expected profile to be removed")
	}

	if _, found := FindProfile(configFile, "client-a"); found {
		t.Fatal("profile still present after removal")
	}
	if len(configFile.DirectoryProfiles) != 0 {
		t.Fatalf("expected directory bindings to be removed, got %+v", configFile.DirectoryProfiles)
	}
	if configFile.ActiveProfile != "" || configFile.LoggedInUserEmail != "" {
		t.Fatalf("expected active pointers to be cleared, got %+v", configFile)
	}
	if len(configFile.LoggedInUsers) != 1 || configFile.LoggedInUsers[0].Email != "other@example.com" {
		t.Fatalf("expected legacy roster cleanup, got %+v", configFile.LoggedInUsers)
	}

	if RemoveProfile(&configFile, "does-not-exist") {
		t.Fatal("expected removal of a missing profile to report false")
	}
}

func TestValidateProfileName(t *testing.T) {
	// Plus-addressed emails are common for shared/test accounts and must be
	// accepted so users can explicitly target their email-named profiles.
	valid := []string{"scott@example.com", "ci+tests@example.com", "client-a", "work.eu", "a", "A1_b-c", "scott@example.com--beta-2"}
	for _, name := range valid {
		if err := ValidateProfileName(name); err != nil {
			t.Fatalf("expected %q to be valid: %v", name, err)
		}
	}

	invalid := []string{"", "-leading-dash", ".leading-dot", "has space", "has/slash", "has:colon"}
	for _, name := range invalid {
		if err := ValidateProfileName(name); err == nil {
			t.Fatalf("expected %q to be invalid", name)
		}
	}
}

func TestOrgMatchesSelector(t *testing.T) {
	cases := []struct {
		selector, id, slug, name string
		want                     bool
	}{
		{"globex", "org-1", "globex-demo", "Globex", true},      // by name
		{"GLOBEX", "org-1", "globex-demo", "Globex", true},      // case-insensitive
		{"globex-demo", "org-1", "globex-demo", "Globex", true}, // by slug
		{"org-1", "org-1", "globex-demo", "Globex", true},       // by id
		{"acme", "org-1", "globex-demo", "Globex", false},
		{"", "org-1", "globex-demo", "Globex", false},
		{"globex", "org-1", "", "", false}, // no metadata to match against
	}

	for _, tc := range cases {
		if got := OrgMatchesSelector(tc.selector, tc.id, tc.slug, tc.name); got != tc.want {
			t.Fatalf("OrgMatchesSelector(%q, %q, %q, %q) = %v, want %v", tc.selector, tc.id, tc.slug, tc.name, got, tc.want)
		}
	}
}

func TestResolveProfileRecordsShadowedBinding(t *testing.T) {
	scopedDir := filepath.Join("/", "home", "scott", "work", "client-a")
	configFile := models.ConfigFile{
		ActiveProfile:     "default-profile",
		Profiles:          []models.Profile{{Name: "default-profile"}, {Name: "client-a"}, {Name: "client-b"}},
		DirectoryProfiles: map[string]string{scopedDir: "client-a"},
	}

	t.Run("an override records the binding it shadowed", func(t *testing.T) {
		resolved := resolveProfileWith(configFile, "client-b", ProfileSourceEnv, scopedDir)
		if resolved.Name != "client-b" {
			t.Fatalf("expected client-b, got %q", resolved.Name)
		}
		if resolved.ShadowedName != "client-a" || resolved.ShadowedScopeDir != scopedDir {
			t.Fatalf("expected the binding to be recorded, got %+v", resolved)
		}
	})

	t.Run("an override matching the binding shadows nothing", func(t *testing.T) {
		resolved := resolveProfileWith(configFile, "client-a", ProfileSourceEnv, scopedDir)
		if resolved.ShadowedName != "" {
			t.Fatalf("expected no shadowed binding, got %+v", resolved)
		}
	})

	t.Run("an override outside any binding shadows nothing", func(t *testing.T) {
		resolved := resolveProfileWith(configFile, "client-b", ProfileSourceEnv, filepath.Join("/", "tmp"))
		if resolved.ShadowedName != "" {
			t.Fatalf("expected no shadowed binding, got %+v", resolved)
		}
	})
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"work":                "'work'",
		"a@x.com":             "'a@x.com'",
		"ci+tests@x.com":      "'ci+tests@x.com'",
		"evil$(whoami)@x.com": `'evil$(whoami)@x.com'`,
		"back`tick`":          "'back`tick`'",
		"it's":                `'it'\''s'`,
		"a; rm -rf /":         "'a; rm -rf /'",
	}
	for in, want := range cases {
		if got := ShellQuote(in); got != want {
			t.Fatalf("ShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeDisplay(t *testing.T) {
	if got := SanitizeDisplay("Acme\x1b[31m evil\x07"); got != "Acme[31m evil" {
		t.Fatalf("escape sequences not stripped: %q", got)
	}
	if got := SanitizeDisplay("line\nbreak"); got != "linebreak" {
		t.Fatalf("newline not stripped: %q", got)
	}
	if got := SanitizeDisplay("Acme / Research"); got != "Acme / Research" {
		t.Fatalf("ordinary text altered: %q", got)
	}
}

func TestOrgMatchTierPrecedence(t *testing.T) {
	if OrgMatchTier("org-1", "org-1", "slug", "name") != orgMatchID {
		t.Fatal("expected an id match to rank highest")
	}
	if OrgMatchTier("slug", "org-1", "slug", "name") != orgMatchSlug {
		t.Fatal("expected a slug match")
	}
	if OrgMatchTier("NAME", "org-1", "slug", "name") != orgMatchName {
		t.Fatal("expected a case-insensitive name match")
	}
	if OrgMatchTier("other", "org-1", "slug", "name") != orgMatchNone {
		t.Fatal("expected no match")
	}
	// An organization named after another one's id must not outrank it.
	if OrgMatchTier("org-1", "attacker-id", "", "org-1") >= OrgMatchTier("org-1", "org-1", "", "") {
		t.Fatal("a name match must rank below an id match")
	}
}

func TestRepointProfileDomain(t *testing.T) {
	base := func() models.ConfigFile {
		return models.ConfigFile{
			ActiveProfile:      "acme-work",
			LoggedInUserEmail:  "scott@example.com",
			LoggedInUserDomain: "https://app.infisical.com/api",
			LoggedInUsers: []models.LoggedInUser{
				{Email: "scott@example.com", Domain: "https://app.infisical.com/api"},
			},
			Profiles: []models.Profile{
				// Same email and instance, different organizations.
				{Name: "acme-work", Email: "scott@example.com", Domain: "https://app.infisical.com/api", OrganizationID: "org-a", OrganizationName: "Acme"},
				{Name: "globex-work", Email: "scott@example.com", Domain: "https://app.infisical.com/api", OrganizationID: "org-b", OrganizationName: "Globex"},
			},
		}
	}

	t.Run("only the named profile moves", func(t *testing.T) {
		configFile := base()
		if !RepointProfileDomain(&configFile, "acme-work", "https://self.example.com/api") {
			t.Fatal("expected the profile to move")
		}
		if configFile.Profiles[0].Domain != "https://self.example.com/api" {
			t.Fatalf("selected profile did not move: %+v", configFile.Profiles[0])
		}
		if configFile.Profiles[1].Domain != "https://app.infisical.com/api" {
			t.Fatalf("a profile sharing the email and instance was moved too: %+v", configFile.Profiles[1])
		}
	})

	t.Run("the organization from the previous instance is dropped", func(t *testing.T) {
		configFile := base()
		RepointProfileDomain(&configFile, "acme-work", "https://self.example.com/api")
		moved := configFile.Profiles[0]
		if moved.OrganizationID != "" || moved.OrganizationName != "" || moved.SubOrganizationID != "" {
			t.Fatalf("expected the organization to be cleared, got %+v", moved)
		}
	})

	t.Run("the legacy roster entry is kept while another profile still uses the old instance", func(t *testing.T) {
		configFile := base()
		RepointProfileDomain(&configFile, "acme-work", "https://self.example.com/api")
		if configFile.LoggedInUsers[0].Domain != "https://app.infisical.com/api" {
			t.Fatalf("roster entry moved while another profile still uses the old instance: %+v", configFile.LoggedInUsers[0])
		}
	})

	t.Run("the legacy roster entry follows the last profile off the old instance", func(t *testing.T) {
		configFile := base()
		configFile.Profiles = configFile.Profiles[:1]
		RepointProfileDomain(&configFile, "acme-work", "https://self.example.com/api")
		if configFile.LoggedInUsers[0].Domain != "https://self.example.com/api" {
			t.Fatalf("roster entry did not follow: %+v", configFile.LoggedInUsers[0])
		}
	})

	t.Run("an unchanged instance or unknown profile is a no-op", func(t *testing.T) {
		configFile := base()
		if RepointProfileDomain(&configFile, "acme-work", "https://app.infisical.com/api") {
			t.Fatal("expected no move for the same instance")
		}
		if RepointProfileDomain(&configFile, "missing", "https://self.example.com/api") {
			t.Fatal("expected no move for an unknown profile")
		}
	})
}
