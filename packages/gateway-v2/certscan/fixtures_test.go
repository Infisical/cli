package certscan

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

type testPKI struct {
	rootKey, interKey, leafKey *ecdsa.PrivateKey
	root, inter, leaf          *x509.Certificate
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	p := testPKI{rootKey: mustKey(t), interKey: mustKey(t), leafKey: mustKey(t)}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{1},
	}
	p.root = mustCert(t, rootTmpl, rootTmpl, &p.rootKey.PublicKey, p.rootKey)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{2},
	}
	p.inter = mustCert(t, interTmpl, p.root, &p.interKey.PublicKey, p.rootKey)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "api.example.com"}, DNSNames: []string{"api.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true,
	}
	p.leaf = mustCert(t, leafTmpl, p.inter, &p.leafKey.PublicKey, p.interKey)
	return p
}

type jksBuilder struct {
	buf bytes.Buffer
}

func (b *jksBuilder) u16(v int) { _ = binary.Write(&b.buf, binary.BigEndian, uint16(v)) }
func (b *jksBuilder) u32(v int) { _ = binary.Write(&b.buf, binary.BigEndian, uint32(v)) }
func (b *jksBuilder) u64(v int) { _ = binary.Write(&b.buf, binary.BigEndian, uint64(v)) }
func (b *jksBuilder) utf(s string) {
	b.u16(len(s))
	b.buf.WriteString(s)
}
func (b *jksBuilder) cert(c *x509.Certificate) {
	b.utf("X.509")
	b.u32(len(c.Raw))
	b.buf.Write(c.Raw)
}

func buildJKS(magic []byte, entries func(b *jksBuilder) int) []byte {
	body := &jksBuilder{}
	count := entries(body)
	out := &jksBuilder{}
	out.buf.Write(magic)
	out.u32(2)
	out.u32(count)
	out.buf.Write(body.buf.Bytes())
	out.buf.Write(make([]byte, 20))
	return out.buf.Bytes()
}
