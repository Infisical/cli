package pam

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testGatewayA = "3f2a9c1e-5b7d-4e8f-a1b2-c3d4e5f60718"
	testGatewayB = "9b8c7d6e-5f4a-4b3c-9d2e-1f0a9b8c7d6e"
)

type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Gateway CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{caCert: cert, caKey: key, caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// issue returns a leaf signed by the CA, carrying a gateway identity URI when gatewayId is set.
func (p *testPKI) issue(t *testing.T, usage x509.ExtKeyUsage, gatewayId string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Gateway"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
	}
	if gatewayId != "" {
		template.URIs = []*url.URL{{Scheme: "urn", Opaque: "infisical:gateway:" + gatewayId}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// handshake dials a gateway presenting a cert issued to answeringGatewayId, expecting expectedGatewayId.
func handshake(t *testing.T, answeringGatewayId, expectedGatewayId string) error {
	t.Helper()
	pki := newTestPKI(t)
	serverCertPEM, serverKeyPEM := pki.issue(t, x509.ExtKeyUsageServerAuth, answeringGatewayId)
	clientCertPEM, clientKeyPEM := pki.issue(t, x509.ExtKeyUsageClientAuth, "")

	serverCert, err := tls.X509KeyPair([]byte(serverCertPEM), []byte(serverKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(pki.caCert)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{string(ALPNInfisicalPAMProxy)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake()
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	server := &BaseProxyServer{}
	conn, err := server.handshakeGatewayConnection(clientConn, ALPNInfisicalPAMProxy, LiveSession{
		GatewayId:              expectedGatewayId,
		GatewayClientCert:      clientCertPEM,
		GatewayClientKey:       clientKeyPEM,
		GatewayServerCertChain: pki.caPEM,
	}, relayServerName, false)
	if conn != nil {
		conn.Close()
	}
	return err
}

func TestGatewayHandshakeAcceptsTheExpectedGateway(t *testing.T) {
	if err := handshake(t, testGatewayA, testGatewayA); err != nil {
		t.Fatalf("expected the handshake to succeed, got %v", err)
	}
}

func TestGatewayHandshakeRejectsAnotherGatewayInTheOrg(t *testing.T) {
	err := handshake(t, testGatewayB, testGatewayA)
	if err == nil || !strings.Contains(err.Error(), "reached a gateway other than '"+testGatewayA+"'") {
		t.Fatalf("expected the handshake to reject gateway B answering for gateway A, got %v", err)
	}
}

func TestGatewayHandshakeAcceptsACertIssuedBeforeGatewayIdentities(t *testing.T) {
	if err := handshake(t, "", testGatewayA); err != nil {
		t.Fatalf("expected a cert without an identity to be accepted, got %v", err)
	}
}

func TestGatewayHandshakeSkipsTheCheckWhenThePlatformSendsNoGatewayId(t *testing.T) {
	if err := handshake(t, testGatewayB, ""); err != nil {
		t.Fatalf("expected the handshake to succeed without a gateway ID, got %v", err)
	}
}
