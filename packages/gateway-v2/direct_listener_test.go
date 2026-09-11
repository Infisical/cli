package gatewayv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}

// Held for the session instead, a few long-lived clients would lock out every later one.
func TestHandshakeSlotReleasedWhenHandshakeResolves(t *testing.T) {
	g := &Gateway{}
	g.tlsConfig.Store(testTLSConfig(t))

	released := make(chan struct{})
	client, server := net.Pipe()
	defer client.Close()

	go g.handleGatewayConnection(server, func() { close(released) })

	// The drain matters: net.Pipe is unbuffered, so a client that stops reading leaves the server
	// blocked writing its alert, and the release would come from the deadline instead.
	go func() {
		c := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		_ = c.Handshake()
		buf := make([]byte, 256)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	select {
	case <-released:
	case <-time.After(directHandshakeTimeout - time.Second):
		t.Fatal("handshake slot was not released on handshake failure")
	}
}

// A return before the handshake resolves still has to free the slot.
func TestHandshakeSlotReleasedWhenTLSConfigIsMissing(t *testing.T) {
	g := &Gateway{}

	released := make(chan struct{})
	_, server := net.Pipe()
	g.handleGatewayConnection(server, func() { close(released) })

	select {
	case <-released:
	default:
		t.Fatal("slot was not released on the early return")
	}
}

func TestHandshakeSlotReleasedOnlyOnce(t *testing.T) {
	g := &Gateway{}
	g.tlsConfig.Store(testTLSConfig(t))

	calls := 0
	_, server := net.Pipe()
	_ = server.Close()
	g.handleGatewayConnection(server, func() { calls++ })

	if calls != 1 {
		t.Fatalf("expected exactly one release, got %d", calls)
	}
}
