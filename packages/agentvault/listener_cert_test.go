package agentvault

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// writeListenerPair writes a certificate and key and moves their mtime on, since a rewrite within the
// filesystem's timestamp resolution would otherwise look unchanged.
func writeListenerPair(t *testing.T, dir string, notAfter time.Time, at time.Time) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM, _ := selfSignedListenerCert(t, "proxy.example.com", notAfter)
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for path, data := range map[string]string{certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	restore := log.Logger
	log.Logger = zerolog.New(&syncWriter{w: &logs})
	t.Cleanup(func() { log.Logger = restore })
	return &logs
}

func TestListenerCertReloadsWhenTheFilesChange(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeListenerPair(t, dir, time.Now().Add(30*24*time.Hour), time.Now().Add(-time.Hour))
	cert, err := LoadListenerCert(OwnCaInput{Cert: certPath, CertSource: "--socks5-tls-cert", Key: keyPath, KeySource: "--socks5-tls-key"})
	if err != nil {
		t.Fatal(err)
	}
	before := cert.Fingerprint()

	writeListenerPair(t, dir, time.Now().Add(90*24*time.Hour), time.Now())
	cert.check(time.Now())
	if cert.Fingerprint() == before {
		t.Fatal("the renewed certificate wasn't loaded")
	}
	if cert.tlsCertificate().Leaf.NotAfter != cert.NotAfter() {
		t.Fatal("the served pair and the reported expiry disagree")
	}
}

func TestListenerCertKeepsServingWhenTheNewFileIsBroken(t *testing.T) {
	logs := captureLogs(t)
	dir := t.TempDir()
	certPath, keyPath := writeListenerPair(t, dir, time.Now().Add(30*24*time.Hour), time.Now().Add(-time.Hour))
	cert, err := LoadListenerCert(OwnCaInput{Cert: certPath, CertSource: "--socks5-tls-cert", Key: keyPath, KeySource: "--socks5-tls-key"})
	if err != nil {
		t.Fatal(err)
	}
	before := cert.Fingerprint()

	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(certPath, now, now); err != nil {
		t.Fatal(err)
	}
	cert.check(now)
	cert.check(now.Add(time.Minute))
	if cert.Fingerprint() != before {
		t.Fatal("a broken file replaced the certificate being served")
	}
	if n := strings.Count(logs.String(), "can't be used; still serving the previous one"); n != 1 {
		t.Fatalf("logged the broken file %d times, want once: %s", n, logs.String())
	}
}

func TestListenerCertWarnsBeforeItExpires(t *testing.T) {
	logs := captureLogs(t)
	certPEM, keyPEM, _ := selfSignedListenerCert(t, "proxy.example.com", time.Now().Add(5*24*time.Hour))
	cert, err := LoadListenerCert(OwnCaInput{Cert: certPEM, CertSource: "--socks5-tls-cert", Key: keyPEM, KeySource: "--socks5-tls-key"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert.check(now)
	cert.check(now.Add(time.Hour))
	if n := strings.Count(logs.String(), "certificate expires in"); n != 1 {
		t.Fatalf("warned %d times within a day, want once: %s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "restart the proxy") {
		t.Fatalf("an inline certificate can't be renewed in place, so the warning should say to restart: %s", logs.String())
	}

	cert.check(now.Add(6 * 24 * time.Hour))
	if !strings.Contains(logs.String(), `"level":"error"`) || !strings.Contains(logs.String(), "has expired") {
		t.Fatalf("no error once expired: %s", logs.String())
	}
}

func TestSocks5ServesTheRenewedCertificateWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeListenerPair(t, dir, time.Now().Add(30*24*time.Hour), time.Now().Add(-time.Hour))
	own, err := LoadListenerCert(OwnCaInput{Cert: certPath, CertSource: "--socks5-tls-cert", Key: keyPath, KeySource: "--socks5-tls-key"})
	if err != nil {
		t.Fatal(err)
	}
	f := newSocks5Fixture(t, &stubResolver{result: &resolveResult{SessionID: "s1"}},
		func(_ *proxyServer, opts *Socks5Options, _ *socks5Server) { opts.Cert = own })
	served := func() string {
		conn, err := tls.Dial("tcp", f.addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return FingerprintOf(conn.ConnectionState().PeerCertificates[0].Raw)
	}

	before := served()
	writeListenerPair(t, dir, time.Now().Add(90*24*time.Hour), time.Now())
	own.check(time.Now())
	if after := served(); after == before || after != own.Fingerprint() {
		t.Fatalf("served %s after the renewal, want the new certificate %s", after, own.Fingerprint())
	}
}
