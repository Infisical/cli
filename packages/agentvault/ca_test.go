package agentvault

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

func generateRootCa() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Infisical Agent Vault Proxy"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

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
		own, err := LoadOwnCa(OwnCaInput{Cert: pair[0], Key: pair[1]})
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
	_, err := LoadOwnCa(OwnCaInput{Cert: "/nowhere/ca.crt", Key: keyPEM})
	if err == nil || !strings.HasPrefix(err.Error(), "--ca-cert is not a PEM, base64 PEM or readable file: /nowhere/ca.crt") {
		t.Fatalf("expected the --ca-cert message, got %v", err)
	}
	_, err = LoadOwnCa(OwnCaInput{Cert: certPEM, Key: "not a key"})
	if err == nil || !strings.HasPrefix(err.Error(), "--ca-key is not a PEM, base64 PEM or readable file") {
		t.Fatalf("expected the --ca-key message, got %v", err)
	}
}

func TestLoadOwnCaDoesNotEchoALongValue(t *testing.T) {
	certPEM, _, _ := caPairPEM(t)
	long := strings.Repeat("k", 500)
	_, err := LoadOwnCa(OwnCaInput{Cert: certPEM, Key: long})
	if err == nil || strings.Contains(err.Error(), long) {
		t.Fatalf("the whole value was echoed back: %v", err)
	}
}

func TestLoadOwnCaRefusesAMismatchedPair(t *testing.T) {
	certPEM, _, _ := caPairPEM(t)
	_, otherKey, _ := caPairPEM(t)
	_, err := LoadOwnCa(OwnCaInput{Cert: certPEM, Key: otherKey})
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

func TestLoadOwnCaNeverEchoesTheKeyValue(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	_, otherKey, _ := caPairPEM(t)
	broken := strings.Replace(keyPEM, "\n", "\nAAAA", 2)
	for name, key := range map[string]string{
		"short value":     "s3cret",
		"not a key":       strings.Repeat("k", 500),
		"damaged PEM":     broken,
		"mismatched pair": otherKey,
	} {
		_, err := LoadOwnCa(OwnCaInput{Cert: certPEM, Key: key})
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		for _, line := range strings.Split(key, "\n") {
			if len(line) > 4 && !strings.HasPrefix(line, "-----") && strings.Contains(err.Error(), line) {
				t.Fatalf("%s: the key value was echoed back: %v", name, err)
			}
		}
	}
	_, err := LoadOwnCa(OwnCaInput{Cert: certPEM, Key: "s3cret"})
	if err == nil || !strings.Contains(err.Error(), "value hidden") {
		t.Fatalf("expected the value to be reported as hidden, got %v", err)
	}
}

func TestLoadOwnCaNamesTheEnvVarItCameFrom(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	_, err := LoadOwnCa(OwnCaInput{Cert: "/nowhere/ca.crt", CertSource: "INFISICAL_AGENT_VAULT_CA_CERT", Key: keyPEM, KeySource: "INFISICAL_AGENT_VAULT_CA_KEY"})
	if err == nil || !strings.HasPrefix(err.Error(), "INFISICAL_AGENT_VAULT_CA_CERT is not") {
		t.Fatalf("expected the cert env var to be named, got %v", err)
	}
	_, err = LoadOwnCa(OwnCaInput{Cert: certPEM, CertSource: "INFISICAL_AGENT_VAULT_CA_CERT", Key: "nope", KeySource: "INFISICAL_AGENT_VAULT_CA_KEY"})
	if err == nil || !strings.HasPrefix(err.Error(), "INFISICAL_AGENT_VAULT_CA_KEY is not") {
		t.Fatalf("expected the key env var to be named, got %v", err)
	}
}

func TestLoadOwnCaSkipsECParametersBeforeTheKey(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	params := string(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}}))
	if _, err := LoadOwnCa(OwnCaInput{Cert: certPEM, Key: params + keyPEM}); err != nil {
		t.Fatalf("a key written by openssl ecparam -genkey was refused: %v", err)
	}
}

func TestLoadOwnCaReadsLiteralNewlinesFromAnEnvVar(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	flat := func(s string) string { return strings.ReplaceAll(s, "\n", `\n`) }
	own, err := LoadOwnCa(OwnCaInput{Cert: flat(certPEM), Key: flat(keyPEM)})
	if err != nil {
		t.Fatalf("PEM with literal \\n sequences was refused: %v", err)
	}
	if string(caPEM(own.cert)) != certPEM {
		t.Fatal("loaded a different certificate")
	}
}

func TestLoadOwnCaWarnsWhenTheCertHoldsABundle(t *testing.T) {
	certPEM, keyPEM, _ := caPairPEM(t)
	otherCert, _, _ := caPairPEM(t)
	own, err := LoadOwnCa(OwnCaInput{Cert: certPEM + otherCert, Key: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if string(caPEM(own.cert)) != certPEM {
		t.Fatal("the first certificate in the bundle is not the one served")
	}
	if len(own.Warnings()) != 1 || !strings.Contains(own.Warnings()[0], "only the first") {
		t.Fatalf("expected a bundle warning, got %v", own.Warnings())
	}

	own, err = LoadOwnCa(OwnCaInput{Cert: certPEM, Key: keyPEM})
	if err != nil || len(own.Warnings()) != 0 {
		t.Fatalf("a single certificate must not warn: %v %v", own.Warnings(), err)
	}
}

func TestLoadOwnCaAcceptsOnlyP256(t *testing.T) {
	selfSigned := func(pub, priv any) string {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "ca"},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	pkcs8 := func(priv any) string {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadOwnCa(OwnCaInput{Cert: selfSigned(&p384.PublicKey, p384), Key: pkcs8(p384)})
	if err == nil || !strings.Contains(err.Error(), "only P-256") || !strings.Contains(err.Error(), "P-384") {
		t.Fatalf("a P-384 key was accepted or reported unclearly: %v", err)
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadOwnCa(OwnCaInput{Cert: selfSigned(edKey.Public(), edKey), Key: pkcs8(edKey)})
	if err == nil || !strings.Contains(err.Error(), "only P-256") {
		t.Fatalf("an Ed25519 key was accepted or reported unclearly: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	_, err = LoadOwnCa(OwnCaInput{Cert: selfSigned(&rsaKey.PublicKey, rsaKey), Key: rsaPEM})
	if err == nil || !strings.Contains(err.Error(), "only P-256") {
		t.Fatalf("an RSA key was accepted or reported unclearly: %v", err)
	}
}

func TestLoadOwnCaRefusesAnExpiredCa(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expired CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	_, err = LoadOwnCa(OwnCaInput{Cert: certPEM, CertSource: "--ca-cert", Key: keyPEM, KeySource: "--ca-key"})
	if err == nil || !strings.Contains(err.Error(), "isn't valid yet or has expired (valid from ") {
		t.Fatalf("an expired CA was accepted or reported unclearly: %v", err)
	}
}
