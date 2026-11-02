package agentvault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	listenerCertCheckEvery   = time.Minute
	listenerCertWarnWithin   = 14 * 24 * time.Hour
	listenerCertWarnEvery    = 24 * time.Hour
	listenerCertExpiredEvery = time.Hour
)

// ListenerCert is the operator's own certificate for the SOCKS5 listener. One read from files is read again
// when a file changes, so renewing it, such as with certbot, needs no restart. Every handshake reads the
// current pair, so a swap never races one in progress.
type ListenerCert struct {
	in      OwnCaInput
	current atomic.Pointer[listenerPair]

	// Only the watch goroutine touches these after LoadListenerCert returns.
	certStamp, keyStamp   fileStamp
	lastWarn, lastExpired time.Time
}

type listenerPair struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
}

// The zero stamp means the value was not a file, which never changes.
type fileStamp struct {
	modTime time.Time
	size    int64
}

func stampOf(v string) fileStamp {
	info, err := os.Stat(v)
	if err != nil || info.IsDir() {
		return fileStamp{}
	}
	return fileStamp{modTime: info.ModTime(), size: info.Size()}
}

func (c *ListenerCert) Fingerprint() string { return FingerprintOf(c.current.Load().leaf.Raw) }

func (c *ListenerCert) NotAfter() time.Time { return c.current.Load().leaf.NotAfter }

func (c *ListenerCert) tlsCertificate() *tls.Certificate { return &c.current.Load().certificate }

func (c *ListenerCert) fromFiles() bool {
	return c.certStamp != (fileStamp{}) || c.keyStamp != (fileStamp{})
}

// Any key type and the full chain, unlike a CA, which has to be an ECDSA P-256 key the proxy can sign with.
func LoadListenerCert(in OwnCaInput) (*ListenerCert, error) {
	pair, err := loadListenerPair(in)
	if err != nil {
		return nil, err
	}
	c := &ListenerCert{in: in, certStamp: stampOf(in.Cert), keyStamp: stampOf(in.Key)}
	c.current.Store(pair)
	return c, nil
}

func loadListenerPair(in OwnCaInput) (*listenerPair, error) {
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
	return &listenerPair{certificate: pair, leaf: leaf}, nil
}

// watch checks right away, so a certificate close to expiry is reported at start, then once a minute.
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
	if c.fromFiles() {
		c.reloadIfChanged()
	}

	notAfter := c.NotAfter()
	renew := "renew it and restart the proxy"
	if c.fromFiles() {
		renew = "renew it in place and the proxy picks it up within a minute"
	}
	switch left := notAfter.Sub(now); {
	case left <= 0:
		if now.Sub(c.lastExpired) >= listenerCertExpiredEvery {
			c.lastExpired = now
			log.Error().Str("door", "socks5").Time("certificateExpiresAt", notAfter).
				Msgf("agent-vault: the SOCKS5 port's certificate has expired, so clients refuse to connect; %s", renew)
		}
	case left < listenerCertWarnWithin:
		if now.Sub(c.lastWarn) >= listenerCertWarnEvery {
			c.lastWarn = now
			log.Warn().Str("door", "socks5").Time("certificateExpiresAt", notAfter).
				Msgf("agent-vault: the SOCKS5 port's certificate expires in %d days; %s", int(left.Hours()/24), renew)
		}
	}
}

// A renewal can write the certificate and the key a moment apart. The stamps move on even when the read
// fails, so the half-written pair is tried once, and the next write of either file tries again.
func (c *ListenerCert) reloadIfChanged() {
	certStamp, keyStamp := stampOf(c.in.Cert), stampOf(c.in.Key)
	if certStamp == c.certStamp && keyStamp == c.keyStamp {
		return
	}
	c.certStamp, c.keyStamp = certStamp, keyStamp
	pair, err := loadListenerPair(c.in)
	if err != nil {
		log.Error().Err(err).Str("door", "socks5").
			Msg("agent-vault: the SOCKS5 port's certificate changed on disk but can't be used; still serving the previous one")
		return
	}
	c.current.Store(pair)
	c.lastWarn, c.lastExpired = time.Time{}, time.Time{}
	log.Info().Str("door", "socks5").
		Str("certificateFingerprint", FingerprintOf(pair.leaf.Raw)).
		Time("certificateExpiresAt", pair.leaf.NotAfter).
		Msg("agent-vault: loaded the SOCKS5 port's renewed certificate")
}
