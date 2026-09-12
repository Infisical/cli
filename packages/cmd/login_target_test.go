package cmd

import (
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
)

func TestResolveLoginTarget(t *testing.T) {
	configFile := models.ConfigFile{
		Profiles: []models.Profile{
			{Name: "work", Email: "a@x.com", Domain: "https://eu.infisical.com/api", OrganizationID: "org-1"},
		},
	}

	t.Run("no flags derive the name after login and may move the default", func(t *testing.T) {
		target, err := resolveLoginTarget("", "", "", configFile)
		if err != nil {
			t.Fatal(err)
		}
		if target.name != "" || target.explicit || target.reauth {
			t.Fatalf("expected an untargeted login, got %+v", target)
		}
	})

	t.Run("--save-as names a new profile without moving the default", func(t *testing.T) {
		target, err := resolveLoginTarget("client-b", "", "", configFile)
		if err != nil {
			t.Fatal(err)
		}
		if target.name != "client-b" || !target.explicit || target.reauth {
			t.Fatalf("unexpected target %+v", target)
		}
	})

	t.Run("--save-as an existing profile replaces it rather than signing back in", func(t *testing.T) {
		target, err := resolveLoginTarget("work", "", "", configFile)
		if err != nil {
			t.Fatal(err)
		}
		if target.name != "work" || target.reauth {
			t.Fatalf("unexpected target %+v", target)
		}
	})

	t.Run("--save-as validates the name", func(t *testing.T) {
		if _, err := resolveLoginTarget("bad name!", "", "", configFile); err == nil {
			t.Fatal("expected an invalid name to be rejected")
		}
	})

	t.Run("--profile signs back in to an existing profile", func(t *testing.T) {
		target, err := resolveLoginTarget("", "work", util.ProfileSourceFlag, configFile)
		if err != nil {
			t.Fatal(err)
		}
		if !target.reauth || !target.explicit || target.name != "work" || target.profile.Domain != "https://eu.infisical.com/api" {
			t.Fatalf("unexpected target %+v", target)
		}
	})

	t.Run("--profile for a missing profile is refused with a --save-as hint", func(t *testing.T) {
		_, err := resolveLoginTarget("", "missing", util.ProfileSourceEnv, configFile)
		if err == nil || !strings.Contains(err.Error(), "--save-as missing") || !strings.Contains(err.Error(), util.ProfileSourceEnv) {
			t.Fatalf("expected a refusal naming the source and the fix, got %v", err)
		}
	})

	t.Run("the --profile flag and --save-as naming different profiles conflict", func(t *testing.T) {
		if _, err := resolveLoginTarget("other", "work", util.ProfileSourceFlag, configFile); err == nil {
			t.Fatal("expected a conflict error")
		}
	})

	t.Run("an ambient INFISICAL_PROFILE does not conflict with --save-as", func(t *testing.T) {
		target, err := resolveLoginTarget("other", "work", util.ProfileSourceEnv, configFile)
		if err != nil {
			t.Fatal(err)
		}
		if target.name != "other" || target.reauth {
			t.Fatalf("expected --save-as to win over the pinned profile, got %+v", target)
		}
	})

	t.Run("both flags naming the same profile save it", func(t *testing.T) {
		target, err := resolveLoginTarget("work", "work", util.ProfileSourceFlag, configFile)
		if err != nil {
			t.Fatal(err)
		}
		if target.name != "work" || target.reauth || !target.explicit {
			t.Fatalf("unexpected target %+v", target)
		}
	})
}
