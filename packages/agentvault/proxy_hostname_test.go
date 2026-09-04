package agentvault

import (
	"bytes"
	"testing"
)

// Matching lowercased and trimmed the trailing dot on its own, while the leaf, the Host header and the
// dial used whatever the client typed. So one host could be brokered under a spelling it was never
// certified for.
func TestTargetsAreNormalizedOnce(t *testing.T) {
	cases := []struct {
		target   string
		wantHost string
		wantPort string
	}{
		{"API.Example.COM:8443", "api.example.com", "8443"},
		{"api.example.com.:8443", "api.example.com", "8443"},
		{"API.Example.COM", "api.example.com", "443"},
		{"api.example.com.", "api.example.com", "443"},
	}
	for _, tc := range cases {
		host, port, err := parseConnectTarget(tc.target)
		if err != nil {
			t.Fatalf("parseConnectTarget(%q): %v", tc.target, err)
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Fatalf("parseConnectTarget(%q) = %q,%q; want %q,%q", tc.target, host, port, tc.wantHost, tc.wantPort)
		}
	}

	host, port, err := parseForwardTarget("API.Example.COM.")
	if err != nil {
		t.Fatalf("parseForwardTarget: %v", err)
	}
	if host != "api.example.com" || port != "80" {
		t.Fatalf("parseForwardTarget = %q,%q; want api.example.com,80", host, port)
	}
}

// Every capitalisation used to mint and cache its own certificate - a P-256 keygen and a signature
// each - so a session holder could churn the leaf cache with case alone.
func TestOneHostMintsOneLeafWhateverTheCase(t *testing.T) {
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatalf("generateRootCa: %v", err)
	}
	ca := newCaManager(key, cert)

	first, err := ca.mintLeaf("api.example.com")
	if err != nil {
		t.Fatalf("mintLeaf: %v", err)
	}

	for _, target := range []string{"API.Example.COM:443", "aPi.ExAmPlE.cOm:443", "api.example.com.:443"} {
		host, _, perr := parseConnectTarget(target)
		if perr != nil {
			t.Fatalf("parseConnectTarget(%q): %v", target, perr)
		}
		again, merr := ca.mintLeaf(host)
		if merr != nil {
			t.Fatalf("mintLeaf(%q): %v", host, merr)
		}
		if !bytes.Equal(again.Certificate[0], first.Certificate[0]) {
			t.Fatalf("%q minted a second certificate instead of reusing the cached one", target)
		}
	}
}
