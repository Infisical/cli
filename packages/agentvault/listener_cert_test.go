package agentvault

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	restore := log.Logger
	log.Logger = zerolog.New(&syncWriter{w: &logs})
	t.Cleanup(func() { log.Logger = restore })
	return &logs
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
		t.Fatalf("the warning should say to restart the proxy: %s", logs.String())
	}

	cert.check(now.Add(6 * 24 * time.Hour))
	if !strings.Contains(logs.String(), `"level":"error"`) || !strings.Contains(logs.String(), "has expired") {
		t.Fatalf("no error once expired: %s", logs.String())
	}
}
