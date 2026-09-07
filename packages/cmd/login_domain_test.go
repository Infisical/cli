package cmd

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
)

// TestPresetDomainSelection drives the domain-selection path the way `login`
// does: root.go's PersistentPreRun runs the configured domain through
// AppendAPIEndpoint into config.INFISICAL_URL, which usePresetDomain then
// normalizes, decides on, and attributes to a source.
//
// configured is the raw value from --domain, INFISICAL_DOMAIN,
// INFISICAL_API_URL, or the 'domain' field in .infisical.json. wantApply false
// means interactive login falls through to the hosting picker.
func TestPresetDomainSelection(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		flagSet    bool
		envName    string
		wantDomain string
		wantApply  bool
		wantLabel  string
	}{
		{
			name:       "default US cloud with no explicit source shows the picker",
			configured: util.INFISICAL_DEFAULT_US_URL,
			wantDomain: util.INFISICAL_DEFAULT_US_URL,
			wantApply:  false,
			wantLabel:  "configuration",
		},
		{
			name:       "EU cloud with no explicit source shows the picker",
			configured: util.INFISICAL_DEFAULT_EU_URL,
			wantDomain: util.INFISICAL_DEFAULT_EU_URL,
			wantApply:  false,
			wantLabel:  "configuration",
		},
		{
			name:       "US cloud from --domain skips the picker",
			configured: util.INFISICAL_DEFAULT_US_URL,
			flagSet:    true,
			wantDomain: util.INFISICAL_DEFAULT_US_URL,
			wantApply:  true,
			wantLabel:  "--domain flag",
		},
		{
			name:       "US cloud from INFISICAL_DOMAIN skips the picker",
			configured: util.INFISICAL_DEFAULT_US_URL,
			envName:    util.INFISICAL_DOMAIN_ENV_NAME,
			wantDomain: util.INFISICAL_DEFAULT_US_URL,
			wantApply:  true,
			wantLabel:  "INFISICAL_DOMAIN environment variable",
		},
		{
			name:       "EU cloud from legacy INFISICAL_API_URL skips the picker",
			configured: util.INFISICAL_DEFAULT_EU_URL,
			envName:    util.LEGACY_INFISICAL_API_URL_ENV_NAME,
			wantDomain: util.INFISICAL_DEFAULT_EU_URL,
			wantApply:  true,
			wantLabel:  "INFISICAL_API_URL environment variable",
		},
		{
			name:       "flag wins when both flag and env are set",
			configured: util.INFISICAL_DEFAULT_EU_URL,
			flagSet:    true,
			envName:    util.INFISICAL_DOMAIN_ENV_NAME,
			wantDomain: util.INFISICAL_DEFAULT_EU_URL,
			wantApply:  true,
			wantLabel:  "--domain flag",
		},
		{
			name:       "self-hosted from .infisical.json is used without prompting",
			configured: "https://infisical.example.com",
			wantDomain: "https://infisical.example.com",
			wantApply:  true,
			wantLabel:  "configuration",
		},
		{
			name:       "self-hosted from INFISICAL_DOMAIN is used without prompting",
			configured: "https://infisical.example.com",
			envName:    util.INFISICAL_DOMAIN_ENV_NAME,
			wantDomain: "https://infisical.example.com",
			wantApply:  true,
			wantLabel:  "INFISICAL_DOMAIN environment variable",
		},
		{
			name:       "self-hosted on a port is used without prompting",
			configured: "http://localhost:8080",
			envName:    util.INFISICAL_DOMAIN_ENV_NAME,
			wantDomain: "http://localhost:8080",
			wantApply:  true,
			wantLabel:  "INFISICAL_DOMAIN environment variable",
		},
		{
			name:       "nothing configured shows the picker",
			configured: "",
			wantDomain: "",
			wantApply:  false,
			wantLabel:  "configuration",
		},
		// A trailing slash or an /api suffix must not disguise a cloud URL as
		// self-hosted, which would skip the picker for a domain the user never
		// explicitly selected.
		{
			name:       "US cloud with a trailing slash still shows the picker",
			configured: util.INFISICAL_DEFAULT_US_URL + "/",
			wantDomain: util.INFISICAL_DEFAULT_US_URL,
			wantApply:  false,
			wantLabel:  "configuration",
		},
		{
			name:       "US cloud with an /api suffix still shows the picker",
			configured: util.INFISICAL_DEFAULT_US_URL + "/api",
			wantDomain: util.INFISICAL_DEFAULT_US_URL,
			wantApply:  false,
			wantLabel:  "configuration",
		},
		{
			name:       "EU cloud with an /api/ suffix still shows the picker",
			configured: util.INFISICAL_DEFAULT_EU_URL + "/api/",
			wantDomain: util.INFISICAL_DEFAULT_EU_URL,
			wantApply:  false,
			wantLabel:  "configuration",
		},
		{
			name:       "cloud with an /api suffix from env still skips the picker",
			configured: util.INFISICAL_DEFAULT_US_URL + "/api/",
			envName:    util.INFISICAL_DOMAIN_ENV_NAME,
			wantDomain: util.INFISICAL_DEFAULT_US_URL,
			wantApply:  true,
			wantLabel:  "INFISICAL_DOMAIN environment variable",
		},
		{
			name:       "self-hosted with an /api/ suffix normalizes and is applied",
			configured: "https://infisical.example.com/api/",
			envName:    util.INFISICAL_DOMAIN_ENV_NAME,
			wantDomain: "https://infisical.example.com",
			wantApply:  true,
			wantLabel:  "INFISICAL_DOMAIN environment variable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsedDomain := normalizePresetDomain(util.AppendAPIEndpoint(tc.configured))
			if parsedDomain != tc.wantDomain {
				t.Errorf("normalized domain = %q, want %q", parsedDomain, tc.wantDomain)
			}

			gotApply := shouldApplyPresetDomain(parsedDomain, tc.flagSet || tc.envName != "")
			if gotApply != tc.wantApply {
				t.Errorf("shouldApplyPresetDomain(%q, flagSet=%v, envName=%q) = %v, want %v",
					parsedDomain, tc.flagSet, tc.envName, gotApply, tc.wantApply)
			}

			gotLabel := presetDomainSourceLabel(tc.flagSet, tc.envName)
			if gotLabel != tc.wantLabel {
				t.Errorf("presetDomainSourceLabel(%v, %q) = %q, want %q", tc.flagSet, tc.envName, gotLabel, tc.wantLabel)
			}
		})
	}
}

// normalizePresetDomain is reached with config.INFISICAL_URL, which
// AppendAPIEndpoint has already stripped of trailing slashes, so
// TestPresetDomainSelection cannot tell which layer did the trimming. These
// cases pin the trimming here too, against raw input.
func TestNormalizePresetDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"https://app.infisical.com", "https://app.infisical.com"},
		{"https://app.infisical.com/", "https://app.infisical.com"},
		{"https://app.infisical.com///", "https://app.infisical.com"},
		{"https://app.infisical.com/api", "https://app.infisical.com"},
		{"https://app.infisical.com/api/", "https://app.infisical.com"},
		{"https://infisical.example.com/api", "https://infisical.example.com"},
		{"http://localhost:8080/api/", "http://localhost:8080"},
		{"/", ""},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizePresetDomain(tc.in); got != tc.want {
				t.Errorf("normalizePresetDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
