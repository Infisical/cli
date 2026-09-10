package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSignedPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestOnlyThePinnedCertificateIsTrusted(t *testing.T) {
	genuine := selfSignedPEM(t, "genuine")
	appended := selfSignedPEM(t, "appended")

	kept, fp, err := agentVaultCaFingerprint(genuine + appended)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, genuineFp, _ := agentVaultCaFingerprint(genuine)
	if fp != genuineFp {
		t.Fatalf("fingerprint must be of the first certificate")
	}
	if string(kept) != genuine {
		t.Fatalf("only the checked certificate may be kept, got %d bytes for a %d byte certificate", len(kept), len(genuine))
	}
	if strings.Count(string(kept), "BEGIN CERTIFICATE") != 1 {
		t.Fatal("exactly one certificate must be written")
	}
}

func TestBuildAgentVaultRunEnvPointsAtTheProxy(t *testing.T) {
	parent := []string{
		"HOME=/home/dev",
		"HTTPS_PROXY=http://stale:3128",
		"NO_PROXY=internal.example.com",
	}
	env := envToMap(buildAgentVaultRunEnv(parent, "10.0.1.5:17323", "agv_tok", "/tmp/ca.pem", "metadata.google.internal"))

	if env["HOME"] != "/home/dev" {
		t.Fatalf("unrelated variables must pass through, got HOME=%q", env["HOME"])
	}
	want := "http://x-agent-vault:agv_tok@10.0.1.5:17323"
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if env[k] != want {
			t.Fatalf("%s = %q, want %q", k, env[k], want)
		}
	}
	for _, part := range []string{"localhost", "127.0.0.1", "internal.example.com", "metadata.google.internal"} {
		if !strings.Contains(env["NO_PROXY"], part) {
			t.Fatalf("NO_PROXY %q must merge the operator's and the flag's entries with the required ones", env["NO_PROXY"])
		}
	}
	for _, k := range caTrustEnvVars {
		if env[k] != "/tmp/ca.pem" {
			t.Fatalf("%s = %q, want the CA path", k, env[k])
		}
	}
}

func TestBuildAgentVaultRunEnvWithoutCaTrustSetsNoTrustVariables(t *testing.T) {
	env := envToMap(buildAgentVaultRunEnv([]string{"SSL_CERT_FILE=/etc/ssl/corp.pem"}, "proxy:17323", "agv_tok", "", ""))
	if env["SSL_CERT_FILE"] != "/etc/ssl/corp.pem" {
		t.Fatalf("--no-ca-trust must leave the operator's own trust variables alone, got %q", env["SSL_CERT_FILE"])
	}
	if _, ok := env["NODE_EXTRA_CA_CERTS"]; ok {
		t.Fatal("no CA variable may be set when no CA file was written")
	}
}

func TestAgentVaultFingerprintsEqualToleratesCopyFormats(t *testing.T) {
	served := "SHA256:9F:2C:AB:00"
	for _, pinned := range []string{"SHA256:9F:2C:AB:00", "sha256:9f:2c:ab:00", "9F2CAB00", " 9f:2c:ab:00 "} {
		if !agentVaultFingerprintsEqual(pinned, served) {
			t.Fatalf("%q should match %q", pinned, served)
		}
	}
	if agentVaultFingerprintsEqual("SHA256:9F:2C:AB:01", served) {
		t.Fatal("a different fingerprint must not match")
	}
	if agentVaultFingerprintsEqual("", served) {
		t.Fatal("an empty pin must never match")
	}
}

// Both halves have to be present or undici, urllib, requests and libcurl send no credentials at all.
func TestAgentVaultProxyURLCarriesTheTokenAsThePassword(t *testing.T) {
	if got := agentVaultProxyURL("10.0.1.5:17323", "agv_a/b"); got != "http://x-agent-vault:agv_a%2Fb@10.0.1.5:17323" {
		t.Fatalf("unexpected proxy URL %q", got)
	}
}

func TestTrimProxySchemeIgnoresCase(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"127.0.0.1:17323", "127.0.0.1:17323"},
		{"http://127.0.0.1:17323", "127.0.0.1:17323"},
		{"https://127.0.0.1:17323", "127.0.0.1:17323"},
		{"HTTPS://127.0.0.1:17323", "127.0.0.1:17323"},
		{"HtTp://proxy.local:17323", "proxy.local:17323"},
		// A host that merely starts with the letters keeps them.
		{"https-proxy.local:17323", "https-proxy.local:17323"},
	} {
		if got := trimProxyScheme(tc.in); got != tc.want {
			t.Errorf("trimProxyScheme(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// pflag discards a lone empty value, so --access-bundle "" parses to an empty slice and only the flag
// set remembers it was given. A blank alongside a real name has to go too, or the one-bundle limit
// reports two to someone who named one.
func TestNonBlankDropsValuesThatNameNothing(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want int
	}{
		{nil, 0},
		{[]string{""}, 0},
		{[]string{"  "}, 0},
		{[]string{"", "real"}, 1},
		{[]string{"a", " ", "b"}, 2},
		{[]string{" spaced "}, 1},
	} {
		if got := nonBlank(tc.in); len(got) != tc.want {
			t.Errorf("nonBlank(%q) kept %d (%q), want %d", tc.in, len(got), got, tc.want)
		}
	}
	if got := nonBlank([]string{" coding-agent "}); got[0] != "coding-agent" {
		t.Errorf("surrounding space should be trimmed, got %q", got[0])
	}
}
