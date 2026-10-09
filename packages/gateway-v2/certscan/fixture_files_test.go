package certscan

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func commonName(t *testing.T, der []byte) string {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c.Subject.CommonName
}

func TestKeytoolJKS(t *testing.T) {
	res := Parse(readFixture(t, "keystore.jks"), nil)
	if res.Status != StatusOK || res.Format != FormatJKS {
		t.Fatalf("unexpected result %+v", res)
	}
	names := map[string]ChainKind{}
	for _, c := range res.Chains {
		names[commonName(t, c.Certificates[0])] = c.Kind
	}
	if len(names) != 2 || names["Fixture Root CA"] != ChainKindCA {
		t.Fatalf("unexpected chains %v", names)
	}
	if names["jks.example.com"] != ChainKindLeaf {
		t.Fatalf("the key entry certificate must be a leaf: %v", names)
	}
}

func TestKeytoolJCEKSReadsCertificatesAfterASecretKey(t *testing.T) {
	res := Parse(readFixture(t, "secrets.jceks"), nil)
	if res.Format != FormatJCEKS || !res.IsKeystore || res.Status != StatusOK || res.Err != "" {
		t.Fatalf("unexpected result %+v", res)
	}
	var names []string
	for _, chain := range res.Chains {
		names = append(names, commonName(t, chain.Certificates[0]))
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"alpha.jceks.example.com", "bravo.jceks.example.com"}) {
		t.Fatalf("expected both certificates stored after the secret key, got %v", names)
	}
}

func TestPKCS12NamedJKSIsDetectedByContent(t *testing.T) {
	data := readFixture(t, "modern.jks")
	if res := Parse(data, nil); res.Format != FormatPKCS12 || res.Status != StatusLocked {
		t.Fatalf("expected a locked PKCS#12, got %+v", res)
	}
	pw := "changeit"
	res := Parse(data, &pw)
	if res.Status != StatusOK || len(res.Chains) == 0 || commonName(t, res.Chains[0].Certificates[0]) != "p12-named-jks.example.com" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestOpenSSLLegacyPFX(t *testing.T) {
	pw := "changeit"
	res := Parse(readFixture(t, "legacy-rc2.pfx"), &pw)
	if res.Status != StatusOK || res.Format != FormatPKCS12 {
		t.Fatalf("unexpected result %+v", res)
	}
	if commonName(t, res.Chains[0].Certificates[0]) != "legacy.example.com" {
		t.Fatal("wrong certificate")
	}
}

func TestCertificateOnlyPKCS12WithoutTrustAttribute(t *testing.T) {
	password := "trust-441"
	wrong := "nope"

	caOnly := readFixture(t, "ca-only-truststore.p12")
	if res := Parse(caOnly, nil); res.Status != StatusLocked {
		t.Fatalf("expected locked without a password, got %+v", res)
	}
	if res := Parse(caOnly, &wrong); res.Status != StatusPasswordFailed {
		t.Fatalf("expected passwordFailed with a wrong password, got %+v", res)
	}
	res := Parse(caOnly, &password)
	if res.Status != StatusOK || res.Format != FormatPKCS12 || !res.IsKeystore || len(res.Chains) != 2 {
		t.Fatalf("expected two CA chains, got %+v", res)
	}
	for _, chain := range res.Chains {
		if chain.Kind != ChainKindCA {
			t.Fatalf("expected CA chains, got %+v", res.Chains)
		}
	}

	leafOnly := Parse(readFixture(t, "leaf-only-nokey.p12"), &password)
	if leafOnly.Status != StatusOK || len(leafOnly.Chains) != 1 || leafOnly.Chains[0].Kind != ChainKindLeaf {
		t.Fatalf("expected one leaf chain, got %+v", leafOnly)
	}
	if commonName(t, leafOnly.Chains[0].Certificates[0]) != "web.pki441.example.com" {
		t.Fatalf("unexpected leaf %+v", leafOnly.Chains)
	}
}

func TestLegacyEncryptedCertificateOnlyPKCS12(t *testing.T) {
	password := "trust-441"
	wrong := "nope"
	for _, name := range []string{"legacy-3des-certonly.p12"} {
		t.Run(name, func(t *testing.T) {
			data := readFixture(t, name)
			if res := Parse(data, nil); res.Status != StatusLocked {
				t.Fatalf("expected locked without a password, got %+v", res)
			}
			if res := Parse(data, &wrong); res.Status != StatusPasswordFailed {
				t.Fatalf("expected passwordFailed with a wrong password, got %+v", res)
			}
			res := Parse(data, &password)
			if res.Status != StatusOK || len(res.Chains) != 2 {
				t.Fatalf("expected two CA chains, got %+v", res)
			}
		})
	}
}
