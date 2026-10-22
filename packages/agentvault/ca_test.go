package agentvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func caPairPEM(t *testing.T) (certPEM, ecKeyPEM, pkcs8KeyPEM string) {
	t.Helper()
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(caPEM(cert)),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))
}

func TestLoadOwnCaAcceptsPEMBase64AndAPath(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	for name, pair := range map[string][2]string{
		"inline PEM": {certPEM, keyPEM},
		"base64 PEM": {b64(certPEM), b64(keyPEM)},
		"file path":  {certPath, keyPath},
		"mixed":      {certPath, b64(keyPEM)},
	} {
		own, err := LoadOwnCa(pair[0], pair[1])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(caPEM(own.cert)) != certPEM {
			t.Fatalf("%s: loaded a different certificate", name)
		}
	}
}

func TestLoadOwnCaNamesTheFlagItCouldNotRead(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	_, err := LoadOwnCa("/nowhere/ca.crt", keyPEM)
	if err == nil || !strings.HasPrefix(err.Error(), "--ca-cert is not a PEM, base64 PEM or readable file: /nowhere/ca.crt") {
		t.Fatalf("expected the --ca-cert message, got %v", err)
	}
	_, err = LoadOwnCa(certPEM, "not a key")
	if err == nil || !strings.HasPrefix(err.Error(), "--ca-key is not a PEM, base64 PEM or readable file") {
		t.Fatalf("expected the --ca-key message, got %v", err)
	}
}

func TestLoadOwnCaDoesNotEchoALongValue(t *testing.T) {
	certPEM, _, _ := caPairPEM(t)
	long := strings.Repeat("k", 500)
	_, err := LoadOwnCa(certPEM, long)
	if err == nil || strings.Contains(err.Error(), long) {
		t.Fatalf("the whole value was echoed back: %v", err)
	}
}

func TestLoadOwnCaRefusesAMismatchedPair(t *testing.T) {
	certPEM, _, _ := caPairPEM(t)
	_, otherKey, _ := caPairPEM(t)
	_, err := LoadOwnCa(certPEM, otherKey)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a mismatched pair was accepted or reported unclearly: %v", err)
	}
}

func TestParseCaPairReadsAPKCS8Key(t *testing.T) {
	certPEM, _, pkcs8 := caPairPEM(t)
	if _, _, err := parseCaPair([]byte(certPEM), []byte(pkcs8)); err != nil {
		t.Fatalf("a PKCS8 key, as Infisical returns it, was refused: %v", err)
	}
}

func TestParseCaPairRefusesACertificateThatIsNotACa(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = parseCaPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err == nil || !strings.Contains(err.Error(), "not a certificate authority") {
		t.Fatalf("a leaf certificate was accepted as a CA: %v", err)
	}
}
