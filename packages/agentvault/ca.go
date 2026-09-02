package agentvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// The root outlives any deployment that will realistically not be redeployed; re-enrolling replaces it.
	rootCaTTL = 5 * 365 * 24 * time.Hour

	leafTTL             = 24 * time.Hour
	leafReuseMargin     = 1 * time.Hour
	maxLeafCacheEntries = 8192
)

// caManager owns the proxy's own root CA and mints leaves for intercepted hosts.
//
// Unlike the proxied-service CA this root is self-signed and per-proxy: nothing is signed by an
// org-wide CA, so there is no remote re-sign path and no runtime dependency on Infisical. With the
// control plane down, a proxy still serves its own CA and an agent with a cached session still works.
// It also caps a key compromise at the agents using this one proxy.
type caManager struct {
	mu       sync.Mutex
	rootKey  *ecdsa.PrivateKey
	rootCert *x509.Certificate

	leafMu    sync.Mutex
	leafCache map[string]*leafEntry
}

type leafEntry struct {
	cert       tls.Certificate
	expiration time.Time
}

// generateRootCa mints a self-signed ECDSA P-256 root. P-256 because rustls-based agents reject some
// other curves outright.
func generateRootCa() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate the certificate authority key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Infisical Agent Vault Proxy"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(rootCaTTL),
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

func caPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func newCaManager(key *ecdsa.PrivateKey, cert *x509.Certificate) *caManager {
	return &caManager{rootKey: key, rootCert: cert, leafCache: make(map[string]*leafEntry)}
}

// RootPEM is the public half, which is public: it is served unauthenticated on the proxy's own listener
// and is what an agent trusts.
func (c *caManager) RootPEM() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rootCert == nil {
		return nil
	}
	return caPEM(c.rootCert)
}

// Fingerprint is the value an operator pins with, in the same form the dashboard shows.
func (c *caManager) Fingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rootCert == nil {
		return ""
	}
	return FingerprintOf(c.rootCert.Raw)
}

func FingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return "SHA256:" + strings.Join(parts, ":")
}

func (c *caManager) mintLeaf(hostname string) (tls.Certificate, error) {
	c.leafMu.Lock()
	if entry, ok := c.leafCache[hostname]; ok && time.Until(entry.expiration) > leafReuseMargin {
		c.leafMu.Unlock()
		return entry.cert, nil
	}
	c.leafMu.Unlock()

	c.mu.Lock()
	rootKey, rootCert := c.rootKey, c.rootCert
	c.mu.Unlock()
	if rootKey == nil || rootCert == nil {
		return tls.Certificate{}, fmt.Errorf("the proxy has no certificate authority loaded")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	notAfter := time.Now().Add(leafTTL)
	// A leaf must never outlive its issuer, or clients reject the chain as the root nears expiry.
	if notAfter.After(rootCert.NotAfter) {
		notAfter = rootCert.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, rootCert, &key.PublicKey, rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{Certificate: [][]byte{der, rootCert.Raw}, PrivateKey: key}

	c.leafMu.Lock()
	c.evictLeavesIfFullLocked(hostname)
	c.leafCache[hostname] = &leafEntry{cert: cert, expiration: notAfter}
	c.leafMu.Unlock()

	return cert, nil
}

func (c *caManager) evictLeavesIfFullLocked(incoming string) {
	if len(c.leafCache) < maxLeafCacheEntries {
		return
	}
	if _, replacing := c.leafCache[incoming]; replacing {
		return
	}

	now := time.Now()
	for host, entry := range c.leafCache {
		if now.After(entry.expiration) {
			delete(c.leafCache, host)
		}
	}
	for host := range c.leafCache {
		if len(c.leafCache) < maxLeafCacheEntries {
			break
		}
		delete(c.leafCache, host)
	}
}
