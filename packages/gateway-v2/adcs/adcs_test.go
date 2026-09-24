package adcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	icertrequestd2 "github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/icertrequestd2/v0"
	"go.mozilla.org/pkcs7"
)

type recordingD2 struct {
	icertrequestd2.CertRequestD2Client
	chain []byte
	reqs  []*icertrequestd2.GetCAPropertyRequest
}

func (f *recordingD2) GetCAProperty(_ context.Context, req *icertrequestd2.GetCAPropertyRequest, _ ...dcerpc.CallOption) (*icertrequestd2.GetCAPropertyResponse, error) {
	f.reqs = append(f.reqs, req)
	return &icertrequestd2.GetCAPropertyResponse{
		PropertyValue: &wcce.CertTransportBlob{Length: uint32(len(f.chain)), Buffer: f.chain},
	}, nil
}

func TestGetChainPemRequestsCurrentSigningCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	d2 := &recordingD2{chain: chain}
	c := &Client{d2: d2}
	pemChain, err := c.getChainPem(context.Background(), "test-ca")
	if err != nil {
		t.Fatal(err)
	}
	if pemChain == "" {
		t.Fatal("expected a PEM chain")
	}

	if len(d2.reqs) != 1 {
		t.Fatalf("expected 1 GetCAProperty call, got %d", len(d2.reqs))
	}
	req := d2.reqs[0]
	if req.PropertyID != crPropCASigCertChain {
		t.Errorf("PropertyID = %#x, want CR_PROP_CASIGCERTCHAIN (%#x)", req.PropertyID, crPropCASigCertChain)
	}
	if req.PropertyIndex != -1 {
		t.Errorf("PropertyIndex = %d, want -1 (current CA signing cert); index 0 returns the original cert's chain on a renewed CA", req.PropertyIndex)
	}
}
