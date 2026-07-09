package agentproxy

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
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
)

// caManager holds the intermediate CA (signed by the org root CA in Infisical) and mints
// short-lived leaf certificates per upstream hostname, presenting the leaf+intermediate chain.
type caManager struct {
	httpClient *resty.Client

	mu               sync.Mutex
	intermediateKey  *ecdsa.PrivateKey
	intermediateCert *x509.Certificate
	intermediateExp  time.Time

	leafMu    sync.Mutex
	leafCache map[string]*leafEntry
}

type leafEntry struct {
	cert       tls.Certificate
	expiration time.Time
}

func newCaManager(httpClient *resty.Client) *caManager {
	return &caManager{
		httpClient: httpClient,
		leafCache:  make(map[string]*leafEntry),
	}
}

// ensureIntermediate lazily generates an intermediate keypair and has Infisical sign it,
// re-signing when it is near expiry.
func (c *caManager) ensureIntermediate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.intermediateCert != nil && time.Until(c.intermediateExp) > 12*time.Hour {
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate intermediate CA key: %w", err)
	}

	pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal intermediate public key: %w", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})

	resp, err := api.CallSignAgentProxyIntermediateCa(c.httpClient, api.SignAgentProxyIntermediateCaRequest{
		PublicKey: string(pubPem),
	})
	if err != nil {
		return fmt.Errorf("failed to get intermediate CA signed: %w", err)
	}

	block, _ := pem.Decode([]byte(resp.Certificate))
	if block == nil {
		return fmt.Errorf("invalid intermediate CA certificate returned")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}

	c.intermediateKey = key
	c.intermediateCert = cert
	c.intermediateExp = cert.NotAfter
	// new intermediate invalidates cached leaves (they chain to the old one)
	c.leafMu.Lock()
	c.leafCache = make(map[string]*leafEntry)
	c.leafMu.Unlock()

	return nil
}

// mintLeaf returns a TLS certificate for the hostname, signed by the intermediate CA,
// with the intermediate appended so the agent can build the chain to the trusted root.
func (c *caManager) mintLeaf(hostname string) (tls.Certificate, error) {
	if err := c.ensureIntermediate(); err != nil {
		return tls.Certificate{}, err
	}

	c.leafMu.Lock()
	if entry, ok := c.leafCache[hostname]; ok && time.Until(entry.expiration) > time.Hour {
		c.leafMu.Unlock()
		return entry.cert, nil
	}
	c.leafMu.Unlock()

	c.mu.Lock()
	interKey := c.intermediateKey
	interCert := c.intermediateCert
	c.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	notAfter := time.Now().Add(24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}

	leafDer, err := x509.CreateCertificate(rand.Reader, template, interCert, &key.PublicKey, interKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{leafDer, interCert.Raw},
		PrivateKey:  key,
	}

	c.leafMu.Lock()
	c.leafCache[hostname] = &leafEntry{cert: cert, expiration: notAfter}
	c.leafMu.Unlock()

	return cert, nil
}
