package agentvault

import (
	"strings"
	"testing"
)

// SplitHostPort accepts a target with no host, and an empty host is this machine to the dialer, so
// without these guards CONNECT :443 mints a leaf for an empty name and reaches a local service.
func TestTargetsWithoutAHostAreRefused(t *testing.T) {
	for _, target := range []string{":443", ":18080", ":", "", "[]:443", ".", ".:18080", "..", "...:443"} {
		if _, _, err := parseConnectTarget(target); err == nil {
			t.Errorf("parseConnectTarget(%q) was accepted", target)
		}
		if _, _, err := parseForwardTarget(target); err == nil {
			t.Errorf("parseForwardTarget(%q) was accepted", target)
		}
	}
}

func TestOrdinaryTargetsStillParse(t *testing.T) {
	for _, tc := range []struct {
		target, host, connectPort, forwardPort string
	}{
		{"api.example.com:8443", "api.example.com", "8443", "8443"},
		{"API.Example.com.", "api.example.com", "443", "80"},
		{"[2001:db8::1]:443", "2001:db8::1", "443", "443"},
	} {
		host, port, err := parseConnectTarget(tc.target)
		if err != nil || host != tc.host || port != tc.connectPort {
			t.Errorf("parseConnectTarget(%q) = %q/%q err=%v", tc.target, host, port, err)
		}
		host, port, err = parseForwardTarget(tc.target)
		if err != nil || host != tc.host || port != tc.forwardPort {
			t.Errorf("parseForwardTarget(%q) = %q/%q err=%v", tc.target, host, port, err)
		}
	}
}

// Dropping the port for a default-port target is the only path that returns a bare host, and a bare
// IPv6 literal is a malformed Host header: nginx answers 400 rather than routing it.
func TestHostHeaderKeepsIPv6Brackets(t *testing.T) {
	for _, tc := range []struct{ scheme, target, want string }{
		{"https", "[2001:db8::1]:443", "[2001:db8::1]"},
		{"http", "[2001:db8::1]:80", "[2001:db8::1]"},
		{"https", "[2001:db8::1]:8443", "[2001:db8::1]:8443"},
		{"https", "api.example.com:443", "api.example.com"},
		{"https", "api.example.com:8443", "api.example.com:8443"},
		{"http", "10.0.1.5:80", "10.0.1.5"},
	} {
		if got := hostHeaderForScheme(tc.scheme, tc.target); got != tc.want {
			t.Errorf("hostHeaderForScheme(%q, %q) = %q, want %q", tc.scheme, tc.target, got, tc.want)
		}
	}
}

func TestHostnamesLongerThanDNSAllowsAreRefused(t *testing.T) {
	label64 := strings.Repeat("a", 64)
	// Four full labels plus a suffix: 4*63 + 3 dots + ".example" = 263 bytes, past the 253 a DNS name allows.
	tooLong := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".example"
	for _, target := range []string{label64 + ".example.com:443", tooLong + ":443"} {
		if _, _, err := parseConnectTarget(target); err == nil {
			t.Errorf("parseConnectTarget(%q) accepted a hostname past the DNS limits", target)
		}
	}
	for _, target := range []string{
		strings.Repeat("a", 63) + ".example.com:443", // a full label is fine
		"my_host.corp:443",                           // underscores are not the proxy's business
		"localhost:443",
		"[2001:db8::1]:443", // IP literals are exempt from the DNS rules
		"10.0.0.1:443",
	} {
		if _, _, err := parseConnectTarget(target); err != nil {
			t.Errorf("parseConnectTarget(%q) should be accepted: %v", target, err)
		}
	}
}
