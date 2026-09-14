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

const directTestHost = "gateway.internal"

// A CA, a server cert carrying the direct address in its SAN, and a client cert from the same CA:
// the shape the platform and the gateway actually present to each other on the direct transport.
func directTestPKI(t *testing.T) (server *tls.Config, client *tls.Config) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	issue := func(cn string, dns []string, ips []net.IP, eku x509.ExtKeyUsage) tls.Certificate {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			DNSNames:     dns,
			IPAddresses:  ips,
		}
		der, certErr := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if certErr != nil {
			t.Fatal(certErr)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}

	// The gateway's server cert names the direct address, matching what $issueGatewayCerts adds.
	serverCert := issue(directTestHost, []string{"localhost", directTestHost}, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth)
	clientCert := issue("infisical-platform", nil, nil, x509.ExtKeyUsageClientAuth)

	server = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	client = &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	return server, client
}

// Every ALPN the gateway serves has to negotiate over the direct transport, where the client sets
// servername to the gateway's own hostname rather than localhost. Certificate verification and ALPN
// selection are separate halves of one handshake, so this covers protocols no feature test reaches.
func TestEveryAlpnNegotiatesOverDirectTransport(t *testing.T) {
	for _, pkcs11 := range []bool{false, true} {
		protos := nextProtosForGateway(pkcs11)
		for _, proto := range protos {
			t.Run(proto, func(t *testing.T) {
				serverCfg, clientCfg := directTestPKI(t)
				serverCfg.NextProtos = protos

				g := &Gateway{}
				g.tlsConfig.Store(serverCfg)

				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()

				go func() {
					conn, acceptErr := ln.Accept()
					if acceptErr != nil {
						return
					}
					tlsConn := tls.Server(conn, g.tlsConfig.Load())
					_ = tlsConn.Handshake()
					<-time.After(300 * time.Millisecond)
					_ = tlsConn.Close()
				}()

				cfg := clientCfg.Clone()
				cfg.ServerName = directTestHost
				cfg.NextProtos = []string{proto}
				c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
				if err != nil {
					t.Fatalf("handshake failed for %s with servername %q: %v", proto, directTestHost, err)
				}
				defer c.Close()

				if got := c.ConnectionState().NegotiatedProtocol; got != proto {
					t.Fatalf("negotiated %q, want %q", got, proto)
				}
			})
		}
	}
}

// pkcs11 is the one conditional entry, so a gateway without the module must not offer it.
func TestPkcs11AlpnIsOfferedOnlyWithTheModuleLoaded(t *testing.T) {
	has := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}
	if has(nextProtosForGateway(false), "infisical-pkcs11") {
		t.Fatal("pkcs11 offered without the module loaded")
	}
	if !has(nextProtosForGateway(true), "infisical-pkcs11") {
		t.Fatal("pkcs11 not offered with the module loaded")
	}
}
