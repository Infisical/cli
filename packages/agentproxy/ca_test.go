package agentproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
)

func installTestIntermediate(t *testing.T, c *caManager, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	c.intermediateKey = key
	c.intermediateCert = cert
	c.intermediateExp = cert.NotAfter
}

func TestEnsureIntermediateFallsBackWhenResignFails(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer failing.Close()
	origURL := config.INFISICAL_URL
	config.INFISICAL_URL = failing.URL
	defer func() { config.INFISICAL_URL = origURL }()

	c := newCaManager(func() string { return "test-token" })
	installTestIntermediate(t, c, time.Now().Add(1*time.Hour))

	if err := c.ensureIntermediate(); err != nil {
		t.Fatalf("expected fallback to the valid intermediate, got error: %v", err)
	}
	leaf, err := c.mintLeaf("api.example.com")
	if err != nil {
		t.Fatalf("expected minting to keep working on the old intermediate, got: %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("expected leaf + intermediate chain, got %d certs", len(leaf.Certificate))
	}
}

func TestEnsureIntermediateFailsWithoutFallback(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer failing.Close()
	origURL := config.INFISICAL_URL
	config.INFISICAL_URL = failing.URL
	defer func() { config.INFISICAL_URL = origURL }()

	c := newCaManager(func() string { return "test-token" })
	if err := c.ensureIntermediate(); err == nil {
		t.Fatal("expected an error when there is no intermediate to fall back to")
	}
}
