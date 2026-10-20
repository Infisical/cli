package agentvault

import (
	"bytes"
	"crypto/x509"
	"testing"
)

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

// == rather than Equal: Equal ignores the monotonic reading, which pauses while the machine sleeps.
func TestALeafExpiryIgnoresTheSleepingClock(t *testing.T) {
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatalf("generateRootCa: %v", err)
	}
	ca := newCaManager(key, cert)

	leaf, err := ca.mintLeaf("api.example.com")
	if err != nil {
		t.Fatalf("mintLeaf: %v", err)
	}
	exp := ca.leafCache["api.example.com"].expiration
	if exp != exp.Round(0) {
		t.Fatal("the cached leaf expiry carries a monotonic reading, so time asleep would not count toward it")
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !exp.Equal(parsed.NotAfter) {
		t.Fatalf("the cache expires the leaf at %v but the certificate says %v", exp, parsed.NotAfter)
	}
}
