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

func caPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func keyMatchesCert(key *ecdsa.PrivateKey, cert *x509.Certificate) bool {
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && certKey.Equal(&key.PublicKey)
}

// Infisical returns its key as PKCS8, while openssl writes an operator's EC key as SEC 1, so both are read.
func parseCaPair(certPEM, keyPEM []byte) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	certBlock := firstPEMBlock(certPEM, func(t string) bool { return t == "CERTIFICATE" })
	if certBlock == nil {
		return nil, nil, errors.New("the certificate is not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, errors.New("the certificate is not a certificate authority: its basic constraints do not allow it to sign")
	}

	key, err := parseCaKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}

	if !keyMatchesCert(key, cert) {
		return nil, nil, errors.New("the certificate does not match the private key")
	}
	return key, cert, nil
}

func firstPEMBlock(data []byte, want func(blockType string) bool) *pem.Block {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil
		}
		if want(block.Type) {
			return block
		}
	}
}

func isPrivateKeyBlock(blockType string) bool {
	return strings.HasSuffix(blockType, "PRIVATE KEY")
}

// openssl ecparam -genkey writes an EC PARAMETERS block ahead of the key, so blocks that hold no key are skipped.
func parseCaKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	keyBlock := firstPEMBlock(keyPEM, isPrivateKeyBlock)
	if keyBlock == nil {
		return nil, errors.New("the private key holds no PEM PRIVATE KEY block")
	}
	var key *ecdsa.PrivateKey
	var err error
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			var ok bool
			if key, ok = parsed.(*ecdsa.PrivateKey); !ok {
				return nil, errors.New("the private key is not an ECDSA key; only P-256 ECDSA keys are supported")
			}
		}
	default:
		return nil, fmt.Errorf("the private key is a %q PEM block; only P-256 ECDSA keys are supported, as EC PRIVATE KEY or PRIVATE KEY", keyBlock.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse the private key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the private key uses the %s curve; only P-256 ECDSA keys are supported", key.Curve.Params().Name)
	}
	return key, nil
}

const pemMarker = "-----BEGIN "

// Tried as inline PEM, then base64 of a PEM, then a file path. DER is not accepted. An env var set from a
// single-line string often carries its line breaks as a literal \n, which PEM decoding would reject.
func loadCaValue(v string) ([]byte, bool) {
	if strings.Contains(v, pemMarker) {
		return []byte(strings.ReplaceAll(v, `\n`, "\n")), true
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
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	warnings []string
}

// Warnings are returned rather than logged because the logger may not be configured yet.
func (o *OwnCa) Warnings() []string { return o.warnings }

// Each source names where its value came from, the flag or the env var, so errors point at the right one.
type OwnCaInput struct {
	Cert       string
	CertSource string
	Key        string
	KeySource  string
}

func LoadOwnCa(in OwnCaInput) (*OwnCa, error) {
	if in.CertSource == "" {
		in.CertSource = "--ca-cert"
	}
	if in.KeySource == "" {
		in.KeySource = "--ca-key"
	}
	certPEM, ok := loadCaValue(in.Cert)
	if !ok {
		return nil, fmt.Errorf("%s is not a PEM, base64 PEM or readable file: %s", in.CertSource, shortenValue(in.Cert))
	}
	// The key is never echoed, not even its start: a value that failed to load may still be most of the key.
	keyPEM, ok := loadCaValue(in.Key)
	if !ok {
		return nil, fmt.Errorf("%s is not a PEM, base64 PEM or readable file (value hidden)", in.KeySource)
	}
	key, cert, err := parseCaPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the certificate authority in %s and %s can't be used: %w", in.CertSource, in.KeySource, err)
	}
	// Leaves are capped at the CA's NotAfter, so an expired CA would start cleanly and fail every agent's TLS.
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("the certificate authority in %s isn't valid yet or has expired (valid from %s to %s)",
			in.CertSource, cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
	}
	own := &OwnCa{key: key, cert: cert}
	if n := countPEMBlocks(certPEM, "CERTIFICATE"); n > 1 {
		own.warnings = append(own.warnings, fmt.Sprintf(
			"%s holds %d certificates; only the first is served as the certificate authority", in.CertSource, n))
	}
	return own, nil
}

func countPEMBlocks(data []byte, blockType string) int {
	n := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return n
		}
		if block.Type == blockType {
			n++
		}
	}
}

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
