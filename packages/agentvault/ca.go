package agentvault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	rootCaTTL = 5 * 365 * 24 * time.Hour

	leafTTL             = 24 * time.Hour
	leafReuseMargin     = 1 * time.Hour
	maxLeafCacheEntries = 8192
)

// caManager owns the proxy's own root CA and mints leaves for intercepted hosts.
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

// P-256 because rustls-based agents reject some other curves outright.
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

func keyMatchesCert(key *ecdsa.PrivateKey, cert *x509.Certificate) bool {
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && certKey.Equal(&key.PublicKey)
}

// Infisical returns its key as PKCS8, while openssl writes an operator's EC key as SEC 1, so both are read.
func parseCaPair(certPEM, keyPEM []byte) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("the certificate is not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, errors.New("the certificate is not a certificate authority: its basic constraints do not allow it to sign")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("the private key is not PEM")
	}
	var key *ecdsa.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			var ok bool
			if key, ok = parsed.(*ecdsa.PrivateKey); !ok {
				return nil, nil, errors.New("the private key is not an ECDSA key")
			}
		}
	default:
		return nil, nil, fmt.Errorf("the private key is a %q PEM block; expected EC PRIVATE KEY or PRIVATE KEY", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the private key: %w", err)
	}

	if !keyMatchesCert(key, cert) {
		return nil, nil, errors.New("the certificate does not match the private key")
	}
	return key, cert, nil
}

const pemMarker = "-----BEGIN "

// Tried as inline PEM, then base64 of a PEM, then a file path. DER is not accepted.
func loadCaValue(v string) ([]byte, bool) {
	if strings.Contains(v, pemMarker) {
		return []byte(v), true
	}
	if decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v), "")); err == nil && bytes.Contains(decoded, []byte(pemMarker)) {
		return decoded, true
	}
	if data, err := os.ReadFile(v); err == nil && bytes.Contains(data, []byte(pemMarker)) {
		return data, true
	}
	return nil, false
}

// OwnCa is a certificate authority the operator brings in place of the one Infisical holds.
type OwnCa struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func LoadOwnCa(certValue, keyValue string) (*OwnCa, error) {
	certPEM, ok := loadCaValue(certValue)
	if !ok {
		return nil, fmt.Errorf("--ca-cert is not a PEM, base64 PEM or readable file: %s", shortenValue(certValue))
	}
	keyPEM, ok := loadCaValue(keyValue)
	if !ok {
		return nil, fmt.Errorf("--ca-key is not a PEM, base64 PEM or readable file: %s", shortenValue(keyValue))
	}
	key, cert, err := parseCaPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the certificate authority in --ca-cert and --ca-key can't be used: %w", err)
	}
	return &OwnCa{key: key, cert: cert}, nil
}

// A value that failed to load may still be most of a private key, so only its start is echoed back.
func shortenValue(v string) string {
	const keep = 64
	if len(v) <= keep {
		return v
	}
	return v[:keep] + "..."
}

func newCaManager(key *ecdsa.PrivateKey, cert *x509.Certificate) *caManager {
	return &caManager{rootKey: key, rootCert: cert, leafCache: make(map[string]*leafEntry)}
}

func (c *caManager) RootPEM() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rootCert == nil {
		return nil
	}
	return caPEM(c.rootCert)
}

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

	// Truncate drops the monotonic reading, which pauses while the machine sleeps and kept serving leaves
	// past their NotAfter, and matches the whole seconds NotAfter is encoded in.
	notAfter := time.Now().Add(leafTTL).Truncate(time.Second)
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
