package agentvault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	listenerCertCheckEvery   = time.Hour
	listenerCertWarnWithin   = 14 * 24 * time.Hour
	listenerCertWarnEvery    = 24 * time.Hour
	listenerCertExpiredEvery = time.Hour
)

// ListenerCert is the operator's own certificate for the SOCKS5 listener, read once at start. A renewed
// certificate takes a restart, so the proxy warns before this one expires.
type ListenerCert struct {
	certificate tls.Certificate
	leaf        *x509.Certificate

	// Only the watch goroutine touches these after LoadListenerCert returns.
	lastWarn, lastExpired time.Time
}

func (c *ListenerCert) Fingerprint() string { return FingerprintOf(c.leaf.Raw) }

func (c *ListenerCert) NotAfter() time.Time { return c.leaf.NotAfter }

// Any key type and the full chain, unlike a CA, which has to be an ECDSA P-256 key the proxy can sign with.
func LoadListenerCert(in OwnCaInput) (*ListenerCert, error) {
	certPEM, ok := loadCaValue(in.Cert)
	if !ok {
		return nil, fmt.Errorf("%s is not a PEM, base64 PEM or readable file: %s", in.CertSource, shortenValue(in.Cert))
	}
	keyPEM, ok := loadCaValue(in.Key)
	if !ok {
		return nil, fmt.Errorf("%s is not a PEM, base64 PEM or readable file (value hidden)", in.KeySource)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the certificate in %s and the key in %s can't be used together: %w", in.CertSource, in.KeySource, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("the certificate in %s can't be parsed: %w", in.CertSource, err)
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate in %s isn't valid yet or has expired (valid from %s to %s)",
			in.CertSource, leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	pair.Leaf = leaf
	return &ListenerCert{certificate: pair, leaf: leaf}, nil
}

// watch checks right away, so a certificate close to expiry is reported at start, then once an hour.
func (c *ListenerCert) watch(stop <-chan struct{}) {
	c.check(time.Now())
	ticker := time.NewTicker(listenerCertCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			c.check(now)
		}
	}
}

func (c *ListenerCert) check(now time.Time) {
	notAfter := c.NotAfter()
	switch left := notAfter.Sub(now); {
	case left <= 0:
		if now.Sub(c.lastExpired) >= listenerCertExpiredEvery {
			c.lastExpired = now
			log.Error().Str("door", "socks5").Time("certificateExpiresAt", notAfter).
				Msg("agent-vault: the SOCKS5 port's certificate has expired, so clients refuse to connect; renew it and restart the proxy")
		}
	case left < listenerCertWarnWithin:
		if now.Sub(c.lastWarn) >= listenerCertWarnEvery {
			c.lastWarn = now
			log.Warn().Str("door", "socks5").Time("certificateExpiresAt", notAfter).
				Msgf("agent-vault: the SOCKS5 port's certificate expires in %d days; renew it and restart the proxy", int(left.Hours()/24))
		}
	}
}
