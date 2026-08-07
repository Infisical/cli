package util

import (
	"reflect"
	"testing"
)

func TestResolveReLoginDomain(t *testing.T) {
	usDefault := AppendAPIEndpoint(INFISICAL_DEFAULT_US_URL)
	euAPI := AppendAPIEndpoint(INFISICAL_DEFAULT_EU_URL)

	tests := []struct {
		name         string
		storedDomain string
		resolvedURL  string
		expected     string
	}{
		{
			// The regression from the reported bug: an expired EU session must
			// re-login against EU, not fall back to the US default.
			name:         "stored EU domain wins over US default",
			storedDomain: euAPI,
			resolvedURL:  usDefault,
			expected:     euAPI,
		},
		{
			name:         "stored self-hosted domain is forwarded",
			storedDomain: "https://vault.example.com/api",
			resolvedURL:  usDefault,
			expected:     "https://vault.example.com/api",
		},
		{
			// --domain / INFISICAL_DOMAIN / .infisical.json, with nothing stored yet.
			name:         "explicit non-default resolved URL is forwarded when nothing is stored",
			storedDomain: "",
			resolvedURL:  euAPI,
			expected:     euAPI,
		},
		{
			// Must stay empty: the US default is what an unconfigured invocation
			// looks like, and forwarding it would skip the region prompt.
			name:         "bare US default is not forwarded",
			storedDomain: "",
			resolvedURL:  usDefault,
			expected:     "",
		},
		{
			name:         "nothing known at all",
			storedDomain: "",
			resolvedURL:  "",
			expected:     "",
		},
		{
			// A user who explicitly logged in to US Cloud should stay pinned there
			// rather than be re-prompted.
			name:         "stored US domain is still forwarded",
			storedDomain: usDefault,
			resolvedURL:  usDefault,
			expected:     usDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveReLoginDomain(tt.storedDomain, tt.resolvedURL); got != tt.expected {
				t.Errorf("resolveReLoginDomain(%q, %q) = %q, expected %q",
					tt.storedDomain, tt.resolvedURL, got, tt.expected)
			}
		})
	}
}

func TestBuildReLoginArgs(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected []string
	}{
		{
			name:     "no domain keeps the original argv",
			domain:   "",
			expected: []string{"login", "--silent"},
		},
		{
			name:     "domain is forwarded as an explicit flag",
			domain:   "https://eu.infisical.com/api",
			expected: []string{"login", "--silent", "--domain", "https://eu.infisical.com/api"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildReLoginArgs(tt.domain); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("buildReLoginArgs(%q) = %v, expected %v", tt.domain, got, tt.expected)
			}
		})
	}
}
