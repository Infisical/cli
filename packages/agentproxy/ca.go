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
	// The backend signs the intermediate with a 7-day TTL; renewing below this threshold keeps
	// the intermediate (and every leaf capped to it) comfortably inside that window.
	intermediateRenewThreshold = 12 * time.Hour
	// Below the renew threshold, a failed re-sign falls back to the current intermediate as long
	// as it stays valid past this margin, so a transient Infisical outage inside the renewal
	// window degrades gracefully instead of failing every mint (including cached-leaf hostnames).
	intermediateFallbackMargin = 5 * time.Minute
	// Minimum time between re-sign attempts while falling back; mints are serialized on c.mu,
	// so retrying on every request would both hammer the sign endpoint and block all minting.
	intermediateRetryInterval = 30 * time.Second
	leafTTL                   = 24 * time.Hour // lifetime of a minted leaf certificate
	leafReuseMargin           = 1 * time.Hour  // minimum remaining lifetime to reuse a cached leaf
)

// caManager holds the intermediate CA (signed by the org root CA in Infisical) and mints
// short-lived leaf certificates per upstream hostname, presenting the leaf+intermediate chain.
type caManager struct {
	// token returns the proxy MI's current access token, refreshed by the caller.
	token func() string

	mu                sync.Mutex
	intermediateKey   *ecdsa.PrivateKey
	intermediateCert  *x509.Certificate
	intermediateExp   time.Time
	lastResignAttempt time.Time // throttles re-sign retries while falling back
	// resignGen increments (under mu) every time a new intermediate is installed. Leaf minters
	// snapshot it alongside the intermediate and only cache a leaf if it is unchanged, so a leaf
	// signed by an outgoing intermediate can never land in leafCache after a re-sign cleared it.
	resignGen atomic.Uint64

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

// ensureIntermediate lazily generates an intermediate keypair and has Infisical sign it,
// re-signing when it is near expiry. A failed re-sign is not fatal while the current
// intermediate remains usable: minting continues on it and the re-sign is retried later.
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

// resignIntermediateLocked generates a fresh keypair, has Infisical sign it with the org root
// CA, and installs it. Caller must hold c.mu.
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
	// TLS clients validate an IP-literal target against the IP SAN, not DNS names.
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

	// Only cache if no re-sign happened since the intermediate was snapshotted: a re-sign clears
	// leafCache, and caching a leaf chained to the outgoing intermediate would resurrect stale
	// state. Serving this leaf directly is still fine; it is valid until the old chain expires.
	c.leafMu.Lock()
	if c.resignGen.Load() == gen {
		c.leafCache[hostname] = &leafEntry{cert: cert, expiration: notAfter}
	}
	c.leafMu.Unlock()

	return cert, nil
}
