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
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

const (
	intermediateRenewThreshold = 12 * time.Hour
	intermediateFallbackMargin = 5 * time.Minute
	intermediateRetryInterval  = 30 * time.Second
	leafTTL                    = 24 * time.Hour
	leafReuseMargin            = 1 * time.Hour
	maxLeafCacheEntries        = 8192
)

type caManager struct {
	token func() string

	mu                sync.Mutex
	intermediateKey   *ecdsa.PrivateKey
	intermediateCert  *x509.Certificate
	intermediateExp   time.Time
	lastResignAttempt time.Time
	resignGen         atomic.Uint64

	leafMu    sync.Mutex
	leafCache map[string]*leafEntry
}

type leafEntry struct {
	cert       tls.Certificate
	expiration time.Time
}

func newCaManager(token func() string) *caManager {
	return &caManager{
		token:     token,
		leafCache: make(map[string]*leafEntry),
	}
}

func (c *caManager) ensureIntermediate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	remaining := time.Until(c.intermediateExp)
	if c.intermediateCert != nil && remaining > intermediateRenewThreshold {
		return nil
	}

	canFallBack := c.intermediateCert != nil && remaining > intermediateFallbackMargin
	if canFallBack && time.Since(c.lastResignAttempt) < intermediateRetryInterval {
		return nil
	}
	c.lastResignAttempt = time.Now()

	if err := c.resignIntermediateLocked(); err != nil {
		if canFallBack {
			log.Warn().Err(err).Msg("failed to renew the intermediate CA; continuing with the current one until it nears expiry")
			return nil
		}
		return err
	}
	return nil
}

func (c *caManager) resignIntermediateLocked() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate intermediate CA key: %w", err)
	}

	pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal intermediate public key: %w", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})

	client := resty.New().SetAuthToken(c.token())
	resp, err := api.CallSignAgentProxyIntermediateCa(client, api.SignAgentProxyIntermediateCaRequest{
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
	c.resignGen.Add(1)
	c.leafMu.Lock()
	c.leafCache = make(map[string]*leafEntry)
	c.leafMu.Unlock()

	return nil
}

func (c *caManager) mintLeaf(hostname string) (tls.Certificate, error) {
	if err := c.ensureIntermediate(); err != nil {
		return tls.Certificate{}, err
	}

	c.leafMu.Lock()
	if entry, ok := c.leafCache[hostname]; ok && time.Until(entry.expiration) > leafReuseMargin {
		c.leafMu.Unlock()
		return entry.cert, nil
	}
	c.leafMu.Unlock()

	c.mu.Lock()
	interKey := c.intermediateKey
	interCert := c.intermediateCert
	gen := c.resignGen.Load()
	c.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	notAfter := time.Now().Add(leafTTL)
	// a leaf must never outlive its issuer, or clients would reject the chain near intermediate expiry
	if notAfter.After(interCert.NotAfter) {
		notAfter = interCert.NotAfter
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

	leafDer, err := x509.CreateCertificate(rand.Reader, template, interCert, &key.PublicKey, interKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{leafDer, interCert.Raw},
		PrivateKey:  key,
	}

	// Skip caching if a re-sign happened since snapshotting: it cleared leafCache and this leaf chains to the outgoing intermediate.
	c.leafMu.Lock()
	if c.resignGen.Load() == gen {
		c.evictLeavesIfFullLocked(hostname)
		c.leafCache[hostname] = &leafEntry{cert: cert, expiration: notAfter}
	}
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
