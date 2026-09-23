package adcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	icertrequestd2 "github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/icertrequestd2/v0"
	"go.mozilla.org/pkcs7"
)

// E_INVALIDARG, what AD CS returns for a signing certificate index that does not exist.
const hrInvalidArg = int32(-2147024809)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte(cn),
	}
	parentCert, signer := tmpl, key
	if parent != nil {
		parentCert, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func issueLeaf(t *testing.T, issuer *testCA) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func degeneratePKCS7(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	der, err := pkcs7.DegenerateCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeD2 answers GetCAProperty(CR_PROP_CASIGCERTCHAIN) from a fixed set of chains keyed
// by PropIndex, the way a CA that has been renewed keeps one chain per signing
// certificate. Indexes it does not know return E_INVALIDARG.
type fakeD2 struct {
	icertrequestd2.CertRequestD2Client
	chains map[int32][]byte
	calls  []int32
}

func (f *fakeD2) GetCAProperty(_ context.Context, req *icertrequestd2.GetCAPropertyRequest, _ ...dcerpc.CallOption) (*icertrequestd2.GetCAPropertyResponse, error) {
	f.calls = append(f.calls, req.PropertyIndex)
	if req.PropertyID != crPropCASigCertChain || req.PropertyType != propTypeBinary {
		return &icertrequestd2.GetCAPropertyResponse{Return: hrInvalidArg}, nil
	}
	blob, ok := f.chains[req.PropertyIndex]
	if !ok {
		return &icertrequestd2.GetCAPropertyResponse{Return: hrInvalidArg}, nil
	}
	return &icertrequestd2.GetCAPropertyResponse{
		PropertyValue: &wcce.CertTransportBlob{Length: uint32(len(blob)), Buffer: blob},
	}, nil
}

func pemSubjects(t *testing.T, chainPem string) []string {
	t.Helper()
	var out []string
	rest := []byte(chainPem)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, cert.Subject.CommonName)
	}
	return out
}

func TestGetChainPem(t *testing.T) {
	root := newTestCA(t, "root", nil)
	original := newTestCA(t, "issuing-v0", root)
	renewed := newTestCA(t, "issuing-v1", root)

	t.Run("returns the current chain when it issued the certificate", func(t *testing.T) {
		d2 := &fakeD2{chains: map[int32][]byte{
			propIndexCurrent: degeneratePKCS7(t, renewed.cert, root.cert),
			0:                degeneratePKCS7(t, original.cert, root.cert),
			1:                degeneratePKCS7(t, renewed.cert, root.cert),
		}}
		c := &Client{d2: d2}

		got, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, renewed))
		if err != nil {
			t.Fatal(err)
		}
		if subjects := pemSubjects(t, got); strings.Join(subjects, ",") != "issuing-v1,root" {
			t.Fatalf("chain subjects = %v, want [issuing-v1 root]", subjects)
		}
		if len(d2.calls) != 1 || d2.calls[0] != propIndexCurrent {
			t.Fatalf("GetCAProperty indexes = %v, want [%d]", d2.calls, propIndexCurrent)
		}
	})

	t.Run("scans signing certificate indexes when the CA rejects the current index", func(t *testing.T) {
		d2 := &fakeD2{chains: map[int32][]byte{
			0: degeneratePKCS7(t, original.cert, root.cert),
			1: degeneratePKCS7(t, renewed.cert, root.cert),
		}}
		c := &Client{d2: d2}

		got, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, renewed))
		if err != nil {
			t.Fatal(err)
		}
		if subjects := pemSubjects(t, got); strings.Join(subjects, ",") != "issuing-v1,root" {
			t.Fatalf("chain subjects = %v, want [issuing-v1 root]", subjects)
		}
	})

	t.Run("falls back to an older signing certificate that issued the certificate", func(t *testing.T) {
		d2 := &fakeD2{chains: map[int32][]byte{
			propIndexCurrent: degeneratePKCS7(t, renewed.cert, root.cert),
			0:                degeneratePKCS7(t, original.cert, root.cert),
			1:                degeneratePKCS7(t, renewed.cert, root.cert),
		}}
		c := &Client{d2: d2}

		got, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, original))
		if err != nil {
			t.Fatal(err)
		}
		if subjects := pemSubjects(t, got); strings.Join(subjects, ",") != "issuing-v0,root" {
			t.Fatalf("chain subjects = %v, want [issuing-v0 root]", subjects)
		}
	})

	t.Run("prefers the newest chain when a renewal reused the CA key", func(t *testing.T) {
		reissued, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber:          big.NewInt(99),
			Subject:               pkix.Name{CommonName: "issuing-v0-renewed"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(48 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			SubjectKeyId:          original.cert.SubjectKeyId,
		}, root.cert, &original.key.PublicKey, root.key)
		if err != nil {
			t.Fatal(err)
		}
		sameKey, err := x509.ParseCertificate(reissued)
		if err != nil {
			t.Fatal(err)
		}
		d2 := &fakeD2{chains: map[int32][]byte{
			0: degeneratePKCS7(t, original.cert, root.cert),
			1: degeneratePKCS7(t, sameKey, root.cert),
		}}
		c := &Client{d2: d2}

		got, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, original))
		if err != nil {
			t.Fatal(err)
		}
		if subjects := pemSubjects(t, got); strings.Join(subjects, ",") != "issuing-v0-renewed,root" {
			t.Fatalf("chain subjects = %v, want [issuing-v0-renewed root]", subjects)
		}
	})

	t.Run("errors when no signing certificate issued the certificate", func(t *testing.T) {
		d2 := &fakeD2{chains: map[int32][]byte{
			propIndexCurrent: degeneratePKCS7(t, original.cert, root.cert),
			0:                degeneratePKCS7(t, original.cert, root.cert),
		}}
		c := &Client{d2: d2}

		_, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, renewed))
		if err == nil || !strings.Contains(err.Error(), "no CA signing certificate") {
			t.Fatalf("err = %v, want no-issuer error", err)
		}
	})

	t.Run("surfaces the CA error when no chain can be read at all", func(t *testing.T) {
		c := &Client{d2: &fakeD2{chains: map[int32][]byte{}}}

		_, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, renewed))
		if err == nil || !strings.HasPrefix(err.Error(), "read CA chain:") {
			t.Fatalf("err = %v, want read CA chain error", err)
		}
	})
}
