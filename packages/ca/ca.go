package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	rootCertFile = "ca.crt.pem"
	rootKeyFile  = "ca.key.pem"
	leafTTL      = 24 * time.Hour
	cacheSize    = 1024
)

type CA struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	certPEM  []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func New(dir string) (*CA, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolving home dir: %w", err)
		}
		dir = filepath.Join(home, ".infisical", "broker", "ca")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating ca dir: %w", err)
	}

	ca := &CA{cache: make(map[string]*tls.Certificate)}

	certPath := filepath.Join(dir, rootCertFile)
	keyPath := filepath.Join(dir, rootKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		if err := ca.load(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("loading existing CA: %w", err)
		}
	} else {
		if err := ca.generate(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("generating new CA: %w", err)
		}
	}
	return ca, nil
}

func (c *CA) CertPEM() []byte {
	return c.certPEM
}

func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := hello.ServerName
	if sni == "" {
		return nil, fmt.Errorf("no SNI provided")
	}

	c.mu.Lock()
	if cert, ok := c.cache[sni]; ok {
		if cert.Leaf != nil && time.Now().Before(cert.Leaf.NotAfter) {
			c.mu.Unlock()
			return cert, nil
		}
		delete(c.cache, sni)
	}
	c.mu.Unlock()

	cert, err := c.mintLeaf(sni)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if len(c.cache) >= cacheSize {
		// evict oldest by clearing the whole cache (simple for PoC)
		c.cache = make(map[string]*tls.Certificate)
	}
	c.cache[sni] = cert
	c.mu.Unlock()

	return cert, nil
}

func (c *CA) mintLeaf(sni string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(sni); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{sni}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.rootCert, &key.PublicKey, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("signing leaf cert: %w", err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, c.rootCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func (c *CA) load(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("reading root cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading root key: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("no PEM block found in cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing root cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("no PEM block found in key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing root key: %w", err)
	}

	c.rootCert = cert
	c.rootKey = key
	c.certPEM = certPEM
	return nil
}

func (c *CA) generate(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating root key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Infisical Broker Root CA"},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("creating root cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parsing root cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling root key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing root cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing root key: %w", err)
	}

	c.rootCert = cert
	c.rootKey = key
	c.certPEM = certPEM
	return nil
}
