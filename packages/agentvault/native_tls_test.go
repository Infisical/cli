package agentvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

func tlsService(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, name, addr string, notAfter time.Time) *resolvedService {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	svc := nativeServiceAt(serviceKindTLS, name, addr)
	svc.native.tlsEnabled, svc.native.tlsVerify = true, true
	svc.native.ca = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	svc.credential = credential{
		kind:        credentialClientCert,
		certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		privateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	return svc
}

// The server replies only once it has read to the end of the request, so the client's half-close must reach it
// without closing the tunnel.
func TestATLSServiceRelaysWithTheClientCertificateAfterAHalfClose(t *testing.T) {
	caKey, caCert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := newCaManager(caKey, caCert).mintLeaf("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{leaf}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		request, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, "reply to "+string(request))
	}()
	svc := tlsService(t, caKey, caCert, "engine", ln.Addr().String(), time.Now().Add(time.Hour))
	ps, client, _ := newNativeProxy(t, []*resolvedService{svc})

	tunnel, err := client.OpenTunnel(context.Background(), "engine")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(tunnel, "request"); err != nil {
		t.Fatal(err)
	}
	closeWrite(tunnel)
	if got, err := io.ReadAll(tunnel); err != nil || string(got) != "reply to request" {
		t.Fatalf("reply %q, %v; want %q", got, err, "reply to request")
	}
	records := nativeRecords(t, ps, 1)
	if len(records) != 1 || records[0].Decision != decisionBrokered || records[0].Native == nil || !strings.Contains(records[0].Native.Note, "not recorded") {
		t.Fatalf("records = %+v, want one brokered row saying the connection opened", records)
	}
}

// Under TLS 1.3 the server checks the client certificate only after the proxy's handshake has finished, so here it
// rejects it once the client has already half-closed, which must still be recorded.
func TestATLSServiceRejectingTheClientCertificateAfterAHalfCloseIsRecorded(t *testing.T) {
	caKey, caCert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := newCaManager(caKey, caCert).mintLeaf("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	halfClosed := make(chan struct{})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leaf},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
			<-halfClosed
			return errors.New("rejected")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake()
	}()
	svc := tlsService(t, caKey, caCert, "engine", ln.Addr().String(), time.Now().Add(time.Hour))
	ps, client, _ := newNativeProxy(t, []*resolvedService{svc})

	tunnel, err := client.OpenTunnel(context.Background(), "engine")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(tunnel, "request")
	closeWrite(tunnel)
	time.Sleep(50 * time.Millisecond)
	close(halfClosed)
	_, _ = io.ReadAll(tunnel)

	records := nativeRecords(t, ps, 2)
	if len(records) != 2 || records[1].Decision != decisionError || records[1].Native == nil || !strings.Contains(records[1].Native.Note, "bad certificate") {
		t.Fatalf("records = %+v, want the opened row and an error row for the rejected certificate", records)
	}
}
