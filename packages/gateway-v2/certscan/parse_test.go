package certscan

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
)

func pemOf(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func assertLeafChain(t *testing.T, chains []Chain, p testPKI) {
	t.Helper()
	var leafChains []Chain
	for _, c := range chains {
		if c.Kind == ChainKindLeaf {
			leafChains = append(leafChains, c)
		}
	}
	if len(leafChains) != 1 {
		t.Fatalf("expected 1 leaf chain, got %d (%+v)", len(leafChains), chains)
	}
	got := leafChains[0].Certificates
	want := [][]byte{p.leaf.Raw, p.inter.Raw, p.root.Raw}
	if len(got) != len(want) {
		t.Fatalf("expected chain of %d, got %d", len(want), len(got))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("chain position %d is wrong", i)
		}
	}
}

func TestParsePEMMixedOrderIgnoresKeys(t *testing.T) {
	p := newTestPKI(t)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(p.leafKey)
	data := bytes.Join([][]byte{pemOf("CERTIFICATE", p.root.Raw), pemOf("PRIVATE KEY", keyDER), pemOf("CERTIFICATE", p.leaf.Raw), pemOf("CERTIFICATE", p.inter.Raw)}, nil)
	res := Parse(data, nil)
	if res.Status != StatusOK || res.Format != FormatPEM || res.IsKeystore {
		t.Fatalf("unexpected result %+v", res)
	}
	assertLeafChain(t, res.Chains, p)
}

func TestParsePEMKeyOnly(t *testing.T) {
	p := newTestPKI(t)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(p.leafKey)
	res := Parse(pemOf("PRIVATE KEY", keyDER), nil)
	if res.Status != StatusNoCertificates {
		t.Fatalf("expected noCertificates, got %s", res.Status)
	}
}

func TestParsePEMStandaloneCA(t *testing.T) {
	p := newTestPKI(t)
	res := Parse(bytes.Join([][]byte{pemOf("CERTIFICATE", p.root.Raw), pemOf("CERTIFICATE", p.inter.Raw)}, nil), nil)
	if res.Status != StatusOK {
		t.Fatalf("unexpected status %s", res.Status)
	}
	for _, c := range res.Chains {
		if c.Kind != ChainKindCA {
			t.Fatalf("expected only CA chains, got %+v", c)
		}
	}
	if len(res.Chains) != 2 {
		t.Fatalf("expected 2 CA chains, got %d", len(res.Chains))
	}
}

func TestParseDER(t *testing.T) {
	p := newTestPKI(t)
	res := Parse(p.leaf.Raw, nil)
	if res.Status != StatusOK || res.Format != FormatDER || len(res.Chains) != 1 || res.Chains[0].Kind != ChainKindLeaf {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestParsePKCS7(t *testing.T) {
	p := newTestPKI(t)
	der, err := pkcs7.DegenerateCertificate(bytes.Join([][]byte{p.inter.Raw, p.leaf.Raw, p.root.Raw}, nil))
	if err != nil {
		t.Fatal(err)
	}
	res := Parse(der, nil)
	if res.Status != StatusOK || res.Format != FormatPKCS7 {
		t.Fatalf("unexpected result %+v", res)
	}
	assertLeafChain(t, res.Chains, p)

	pemRes := Parse(pemOf("PKCS7", der), nil)
	if pemRes.Status != StatusOK || pemRes.Format != FormatPKCS7 {
		t.Fatalf("unexpected PEM PKCS7 result %+v", pemRes)
	}
	assertLeafChain(t, pemRes.Chains, p)
}

func TestParsePKCS12Passwords(t *testing.T) {
	p := newTestPKI(t)
	pfx, err := pkcs12.Modern.Encode(p.leafKey, p.leaf, []*x509.Certificate{p.inter, p.root}, "s3cret")
	if err != nil {
		t.Fatal(err)
	}

	if res := Parse(pfx, nil); res.Status != StatusLocked || res.Format != FormatPKCS12 || !res.IsKeystore {
		t.Fatalf("expected locked, got %+v", res)
	}
	wrong := "nope"
	if res := Parse(pfx, &wrong); res.Status != StatusPasswordFailed {
		t.Fatalf("expected passwordFailed, got %s", res.Status)
	}
	right := "s3cret"
	res := Parse(pfx, &right)
	if res.Status != StatusOK {
		t.Fatalf("expected ok, got %+v", res)
	}
	assertLeafChain(t, res.Chains, p)
}

func TestParsePKCS12WithoutPassword(t *testing.T) {
	p := newTestPKI(t)
	pfx, err := pkcs12.Passwordless.Encode(p.leafKey, p.leaf, []*x509.Certificate{p.inter}, "")
	if err != nil {
		t.Fatal(err)
	}
	res := Parse(pfx, nil)
	if res.Status != StatusOK {
		t.Fatalf("expected ok, got %+v", res)
	}
}

func TestParsePKCS12TrustStore(t *testing.T) {
	p := newTestPKI(t)
	pfx, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{p.root, p.inter}, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	pw := "changeit"
	res := Parse(pfx, &pw)
	if res.Status != StatusOK || len(res.Chains) != 2 {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestParseJKS(t *testing.T) {
	p := newTestPKI(t)
	data := buildJKS(jksMagic, func(b *jksBuilder) int {
		b.u32(jksTagPrivateKey)
		b.utf("server")
		b.u64(0)
		b.u32(4)
		b.buf.Write([]byte{9, 9, 9, 9})
		b.u32(2)
		b.cert(p.leaf)
		b.cert(p.inter)
		b.u32(jksTagTrustedCert)
		b.utf("root")
		b.u64(0)
		b.cert(p.root)
		return 2
	})
	res := Parse(data, nil)
	if res.Status != StatusOK || res.Format != FormatJKS || !res.IsKeystore {
		t.Fatalf("unexpected result %+v", res)
	}
	if len(res.Chains) != 2 || res.Chains[0].Kind != ChainKindLeaf || len(res.Chains[0].Certificates) != 2 || res.Chains[1].Kind != ChainKindCA {
		t.Fatalf("unexpected chains %+v", res.Chains)
	}
}

func TestParseJKSSkipsACertificateGoCannotParse(t *testing.T) {
	p := newTestPKI(t)
	bad := func(b *jksBuilder) {
		b.utf("X.509")
		b.u32(3)
		b.buf.Write([]byte{0x30, 0x01, 0x00})
	}
	data := buildJKS(jksMagic, func(b *jksBuilder) int {
		b.u32(jksTagTrustedCert)
		b.utf("broken")
		b.u64(0)
		bad(b)
		b.u32(jksTagTrustedCert)
		b.utf("root")
		b.u64(0)
		b.cert(p.root)
		b.u32(jksTagPrivateKey)
		b.utf("server")
		b.u64(0)
		b.u32(4)
		b.buf.Write([]byte{9, 9, 9, 9})
		b.u32(2)
		bad(b)
		b.cert(p.inter)
		b.u32(jksTagPrivateKey)
		b.utf("api")
		b.u64(0)
		b.u32(4)
		b.buf.Write([]byte{9, 9, 9, 9})
		b.u32(2)
		b.cert(p.leaf)
		bad(b)
		return 4
	})
	res := Parse(data, nil)
	if res.Status != StatusOK || res.Err != "" {
		t.Fatalf("unexpected result %+v", res)
	}
	var leaves, cas int
	for _, c := range res.Chains {
		switch {
		case c.Kind == ChainKindLeaf && len(c.Certificates) == 1 && commonName(t, c.Certificates[0]) == "api.example.com":
			leaves++
		case c.Kind == ChainKindCA:
			cas++
		default:
			t.Fatalf("unexpected chain %+v", c)
		}
	}
	if leaves != 1 || cas != 2 {
		t.Fatalf("expected the api leaf plus the root and intermediate as CAs, got %+v", res.Chains)
	}
}

func TestParseJCEKSKeepsCertificatesBeforeAnUnreadableSecretKey(t *testing.T) {
	p := newTestPKI(t)
	data := buildJKS(jceksMagic, func(b *jksBuilder) int {
		b.u32(jksTagTrustedCert)
		b.utf("root")
		b.u64(0)
		b.cert(p.root)
		b.u32(jksTagSecretKey)
		b.utf("aes")
		b.u64(0)
		b.buf.Write([]byte{0xAC, 0xED, 0, 5})
		return 2
	})
	res := Parse(data, nil)
	if res.Status != StatusOK || res.Format != FormatJCEKS || len(res.Chains) != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestParseJKSTruncated(t *testing.T) {
	p := newTestPKI(t)
	data := buildJKS(jksMagic, func(b *jksBuilder) int {
		b.u32(jksTagTrustedCert)
		b.utf("root")
		b.u64(0)
		b.cert(p.root)
		return 1
	})
	res := Parse(data[:len(data)-200], nil)
	if res.Status != StatusParseError {
		t.Fatalf("expected parseError, got %+v", res)
	}
}

func TestParseTextAndEmptyFilesHoldNoCertificates(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("hello world\n"), []byte("# CA bundle, intentionally empty\n"), []byte("0 1 * * * /usr/bin/renew-certs\n")} {
		res := Parse(data, nil)
		if res.Status != StatusNoCertificates || res.IsKeystore {
			t.Fatalf("expected noCertificates for %q, got %+v", data, res)
		}
	}
}

func TestParseUnknownASN1IsAnUnsupportedKeystore(t *testing.T) {
	res := Parse([]byte{0x30, 0x81, 0x03, 0x02, 0x01, 0x05}, nil)
	if res.Status != StatusUnsupported || !res.IsKeystore {
		t.Fatalf("expected an unsupported keystore, got %+v", res)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	f.Add(append(append([]byte{}, jksMagic...), 0, 0, 0, 2, 0, 0, 0, 1))
	f.Add(append(append([]byte{}, jceksMagic...), 0, 0, 0, 2, 0, 0, 3, 232))
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Parse(data, nil)
	})
}

func TestSelfSignedClassification(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		tmpl *x509.Certificate
		want ChainKind
	}{
		{
			name: "self-signed server certificate marked CA with a SAN",
			tmpl: &x509.Certificate{
				SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "web.example.com"}, DNSNames: []string{"web.example.com"},
				NotBefore: now, NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			},
			want: ChainKindLeaf,
		},
		{
			name: "root with an email SAN",
			tmpl: &x509.Certificate{
				SerialNumber: big.NewInt(13), Subject: pkix.Name{CommonName: "Email Root"}, EmailAddresses: []string{"pki@example.com"},
				NotBefore: now, NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			},
			want: ChainKindCA,
		},
		{
			name: "self-signed certificate without basic constraints or cert sign",
			tmpl: &x509.Certificate{
				SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "legacy"},
				NotBefore: now, NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			},
			want: ChainKindLeaf,
		},
		{
			name: "self-signed root without basic constraints",
			tmpl: &x509.Certificate{
				SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "Old Root"},
				NotBefore: now, NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign,
			},
			want: ChainKindCA,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := mustKey(t)
			cert := mustCert(t, tc.tmpl, tc.tmpl, &key.PublicKey, key)
			chains := buildChains([]*x509.Certificate{cert})
			if len(chains) != 1 || chains[0].Kind != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, chains)
			}
		})
	}
}

func TestKeyOwningChainIsAlwaysLeaf(t *testing.T) {
	p := newTestPKI(t)
	chains := chainFromOrdered([]*x509.Certificate{p.inter, p.root})
	if len(chains) != 1 || chains[0].Kind != ChainKindLeaf || len(chains[0].Certificates) != 2 {
		t.Fatalf("unexpected chains %+v", chains)
	}
}

func TestPKCS12WithExcessiveKDFWorkSkipsTheLibraryDecoder(t *testing.T) {
	p := newTestPKI(t)
	pfx, err := pkcs12.Modern.Encode(p.leafKey, p.leaf, []*x509.Certificate{p.inter}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !pkcs12KDFWorkWithinLimit(pfx) {
		t.Fatal("expected an ordinary keystore to fit the KDF budget")
	}
	var parsed p12PFX
	if _, err := asn1.Unmarshal(pfx, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.MacData.Iterations = 1 << 30
	patched, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if pkcs12KDFWorkWithinLimit(patched) {
		t.Fatal("expected a MAC with 2^30 iterations to exceed the KDF budget")
	}
	start := time.Now()
	res := Parse(patched, nil)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("parsing took %s", elapsed)
	}
	if res.Status != StatusLocked {
		t.Fatalf("expected locked, got %+v", res)
	}
}
