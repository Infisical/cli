package util

import (
	"os"
	"testing"
)

func TestWorkspaceConfigDomain(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		wantDomain string
	}{
		{"domain field is parsed", "testdata/infisical-with-domain.json", "https://custom.infisical.com"},
		{"existing config without a domain field parses to empty", "testdata/infisical-default-env.json", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := GetWorkspaceConfigByPath(tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Domain != tc.wantDomain {
				t.Errorf("Domain = %q, want %q", cfg.Domain, tc.wantDomain)
			}
		})
	}
}

func TestGetEnvDomain(t *testing.T) {
	const unset = "\x00" // sentinel: leave the env var unset for this case

	cases := []struct {
		name    string
		domain  string // INFISICAL_DOMAIN
		apiURL  string // INFISICAL_API_URL (legacy)
		wantVal string
		wantEnv string
		wantOk  bool
	}{
		{"prefers INFISICAL_DOMAIN over legacy", "https://domain.infisical.com", "https://apiurl.infisical.com", "https://domain.infisical.com", INFISICAL_DOMAIN_ENV_NAME, true},
		{"falls back to legacy INFISICAL_API_URL", unset, "https://apiurl.infisical.com", "https://apiurl.infisical.com", LEGACY_INFISICAL_API_URL_ENV_NAME, true},
		{"blank INFISICAL_DOMAIN falls through to legacy", "  ", "https://apiurl.infisical.com", "https://apiurl.infisical.com", LEGACY_INFISICAL_API_URL_ENV_NAME, true},
		{"neither set", unset, unset, "", "", false},
		{"both blank are treated as unset", "  ", "  ", "", "", false},
	}

	setOrUnset := func(t *testing.T, key, val string) {
		t.Helper()
		t.Setenv(key, "") // register restore-on-cleanup, then mutate freely below
		if val == unset {
			os.Unsetenv(key)
			return
		}
		os.Setenv(key, val)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setOrUnset(t, INFISICAL_DOMAIN_ENV_NAME, tc.domain)
			setOrUnset(t, LEGACY_INFISICAL_API_URL_ENV_NAME, tc.apiURL)

			got, ok := GetEnvDomain()
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOk)
			}
			if got != tc.wantVal {
				t.Errorf("value = %q, want %q", got, tc.wantVal)
			}

			gotDomain, gotEnv, gotOk := GetEnvDomainSource()
			if gotOk != tc.wantOk {
				t.Fatalf("GetEnvDomainSource ok = %v, want %v", gotOk, tc.wantOk)
			}
			if gotDomain != tc.wantVal {
				t.Errorf("GetEnvDomainSource value = %q, want %q", gotDomain, tc.wantVal)
			}
			if gotEnv != tc.wantEnv {
				t.Errorf("GetEnvDomainSource env = %q, want %q", gotEnv, tc.wantEnv)
			}
		})
	}
}

func TestGetDomainFromWorkspaceFile(t *testing.T) {
	cases := []struct {
		name       string
		contents   string
		wantDomain string
		wantUsable bool
	}{
		{"https domain is usable", `{"domain":"https://eu.infisical.com"}`, "https://eu.infisical.com", true},
		{"http domain is usable", `{"domain":"http://localhost:8080"}`, "http://localhost:8080", true},
		{"domain with an /api suffix is usable", `{"domain":"https://eu.infisical.com/api/"}`, "https://eu.infisical.com/api/", true},
		{"absent domain is not usable", `{"defaultEnvironment":"dev"}`, "", false},
		{"schemeless domain is reported unusable", `{"domain":"eu.infisical.com"}`, "eu.infisical.com", false},
		{"whitespace domain is reported unusable", `{"domain":"   "}`, "   ", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeWorkspace(t, tc.contents)

			gotDomain, gotUsable := GetDomainFromFile()
			if gotDomain != tc.wantDomain {
				t.Errorf("domain = %q, want %q", gotDomain, tc.wantDomain)
			}
			if gotUsable != tc.wantUsable {
				t.Errorf("usable = %v, want %v", gotUsable, tc.wantUsable)
			}
		})
	}
}
