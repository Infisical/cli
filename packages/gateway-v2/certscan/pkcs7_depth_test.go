package certscan

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

func TestParsePKCS7RejectsDeeplyNested(t *testing.T) {
	deep := bytes.Repeat([]byte{0x30, 0x80}, maxPKCS7NestingDepth+100)
	if _, err := parsePKCS7(deep); !errors.Is(err, errPKCS7TooDeeplyNested) {
		t.Fatalf("expected %v, got %v", errPKCS7TooDeeplyNested, err)
	}
}

func TestParsePKCS7RejectsDefiniteWorkBomb(t *testing.T) {
	payload := []byte{0x30, 0x81, 0xf0}
	for range 40 {
		payload = append(payload, 0x30, 0x04, 0x30, 0x80, 0x00, 0x00)
	}
	if _, err := parsePKCS7(payload); err == nil {
		t.Fatal("expected the re-walk work bomb to be rejected")
	}
}

func TestParsePKCS7RejectsNestedIndefiniteWorkBomb(t *testing.T) {
	payload := bytes.Repeat([]byte{0x30, 0x80}, 100000)
	payload = append(payload, 0x05, 0x00)
	payload = append(payload, bytes.Repeat([]byte{0x00, 0x00}, 100000)...)
	if _, err := parsePKCS7(payload); err == nil {
		t.Fatal("expected the nested indefinite work bomb to be rejected")
	}
}

func TestParsePKCS7RejectsChildExceedingParent(t *testing.T) {
	payload := []byte{0x30, 0x02, 0x04, 0x7f}
	payload = append(payload, bytes.Repeat([]byte{0x00}, 0x7f)...)
	if _, err := parsePKCS7(payload); !errors.Is(err, errPKCS7MalformedBER) {
		t.Fatalf("expected %v, got %v", errPKCS7MalformedBER, err)
	}
}

func TestParsePKCS7RejectsPrimitiveIndefinite(t *testing.T) {
	payload := []byte{0x30, 0x80, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00}
	if _, err := parsePKCS7(payload); !errors.Is(err, errPKCS7MalformedBER) {
		t.Fatalf("expected %v, got %v", errPKCS7MalformedBER, err)
	}
}

func TestParsePKCS7HandlesOverlongLength(t *testing.T) {
	if _, err := parsePKCS7([]byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xfa}); !errors.Is(err, errPKCS7MalformedBER) {
		t.Fatalf("expected %v, got %v", errPKCS7MalformedBER, err)
	}
}

func TestParsePKCS7AllowsLargeShallowIndefinite(t *testing.T) {
	input := []byte{0x30, 0x80}
	input = append(input, bytes.Repeat([]byte{0x04, 0x01, 0x00}, 300000)...)
	input = append(input, 0x00, 0x00)
	if err := ensurePKCS7NestingWithinLimit(input); err != nil {
		t.Fatalf("large shallow bundle must be accepted, got %v", err)
	}
}

func TestParsePKCS7AllowsRealCertificateBundle(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "discovery.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	degenerate, err := pkcs7.DegenerateCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := ensurePKCS7NestingWithinLimit(degenerate); err != nil {
		t.Fatalf("a well-formed certificate bundle must be accepted, got %v", err)
	}
	parsed, err := parsePKCS7(degenerate)
	if err != nil {
		t.Fatalf("parsePKCS7 failed on a real bundle: %v", err)
	}
	if len(parsed.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(parsed.Certificates))
	}
}
