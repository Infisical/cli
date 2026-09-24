package adcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
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
// certificate, and CR_PROP_CASIGCERTCOUNT with the number of non-negative indexes it
// knows (or countBuf verbatim when set). Indexes it does not know return E_INVALIDARG;
// an index in broken returns a transport error. Request2 issues the certificate in
// issued as a PKCS#7 bundle.
type fakeD2 struct {
	icertrequestd2.CertRequestD2Client
	chains   map[int32][]byte
	broken   map[int32]bool
	countBuf []byte
	issued   []byte
	calls    []int32
}

func (f *fakeD2) Request2(_ context.Context, _ *icertrequestd2.Request2Request, _ ...dcerpc.CallOption) (*icertrequestd2.Request2Response, error) {
	return &icertrequestd2.Request2Response{
		RequestID:   42,
		Disposition: dispositionIssued,
		EncodedCert: &wcce.CertTransportBlob{Length: uint32(len(f.issued)), Buffer: f.issued},
	}, nil
}

func (f *fakeD2) GetCAProperty(_ context.Context, req *icertrequestd2.GetCAPropertyRequest, _ ...dcerpc.CallOption) (*icertrequestd2.GetCAPropertyResponse, error) {
	if req.PropertyID == crPropCASigCertCount && req.PropertyType == propTypeLong {
		buf := f.countBuf
		if buf == nil {
			var count uint32
			for idx := range f.chains {
				if idx >= 0 {
					count++
				}
			}
			buf = binary.LittleEndian.AppendUint32(nil, count)
		}
		return &icertrequestd2.GetCAPropertyResponse{
			PropertyValue: &wcce.CertTransportBlob{Length: uint32(len(buf)), Buffer: buf},
		}, nil
	}
	f.calls = append(f.calls, req.PropertyIndex)
	if req.PropertyID != crPropCASigCertChain || req.PropertyType != propTypeBinary {
		return &icertrequestd2.GetCAPropertyResponse{Return: hrInvalidArg}, nil
	}
	if f.broken[req.PropertyIndex] {
		return nil, errors.New("rpc: connection reset")
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
		if len(d2.calls) != 2 || d2.calls[0] != propIndexCurrent || d2.calls[1] != 1 {
			t.Fatalf("GetCAProperty indexes = %v, want [%d 1]", d2.calls, propIndexCurrent)
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
		// Index 1 is the chain PropIndex -1 already returned, so the scan starts below it.
		if len(d2.calls) != 2 || d2.calls[0] != propIndexCurrent || d2.calls[1] != 0 {
			t.Fatalf("GetCAProperty indexes = %v, want [%d 0]", d2.calls, propIndexCurrent)
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

	t.Run("surfaces a read failure during the scan instead of settling for an older chain", func(t *testing.T) {
		d2 := &fakeD2{
			chains: map[int32][]byte{
				0: degeneratePKCS7(t, original.cert, root.cert),
				1: degeneratePKCS7(t, renewed.cert, root.cert),
				2: degeneratePKCS7(t, renewed.cert, root.cert),
			},
			broken: map[int32]bool{2: true},
		}
		c := &Client{d2: d2}

		_, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, original))
		if err == nil || !strings.Contains(err.Error(), "connection reset") {
			t.Fatalf("err = %v, want the transport error", err)
		}
	})

	t.Run("surfaces a transport error on the current index instead of scanning", func(t *testing.T) {
		d2 := &fakeD2{
			chains: map[int32][]byte{0: degeneratePKCS7(t, original.cert, root.cert)},
			broken: map[int32]bool{propIndexCurrent: true},
		}
		c := &Client{d2: d2}

		_, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, original))
		if err == nil || !strings.Contains(err.Error(), "connection reset") {
			t.Fatalf("err = %v, want the transport error", err)
		}
		if len(d2.calls) != 1 {
			t.Fatalf("GetCAProperty indexes = %v, want only [%d]", d2.calls, propIndexCurrent)
		}
	})

	t.Run("returns the current chain as a fallback when no signing certificate issued the certificate", func(t *testing.T) {
		d2 := &fakeD2{chains: map[int32][]byte{
			propIndexCurrent: degeneratePKCS7(t, original.cert, root.cert),
			0:                degeneratePKCS7(t, original.cert, root.cert),
		}}
		c := &Client{d2: d2}

		got, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, renewed))
		if err == nil || !strings.Contains(err.Error(), "none of the 1 CA signing certificate(s)") {
			t.Fatalf("err = %v, want no-issuer error", err)
		}
		if subjects := pemSubjects(t, got); strings.Join(subjects, ",") != "issuing-v0,root" {
			t.Fatalf("fallback chain subjects = %v, want [issuing-v0 root]", subjects)
		}
	})

	t.Run("rejects a zero signing certificate count as a protocol error", func(t *testing.T) {
		d2 := &fakeD2{chains: map[int32][]byte{}}
		c := &Client{d2: d2}

		got, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, renewed))
		if err == nil || !strings.Contains(err.Error(), "CA reported 0 signing certificates") {
			t.Fatalf("err = %v, want count error", err)
		}
		if got != "" {
			t.Fatalf("fallback chain = %q, want empty", got)
		}
		if len(d2.calls) != 1 || d2.calls[0] != propIndexCurrent {
			t.Fatalf("GetCAProperty indexes = %v, want [%d]", d2.calls, propIndexCurrent)
		}
	})

	t.Run("rejects an implausible signing certificate count without scanning", func(t *testing.T) {
		d2 := &fakeD2{
			chains:   map[int32][]byte{0: degeneratePKCS7(t, original.cert, root.cert)},
			countBuf: binary.LittleEndian.AppendUint32(nil, 0x7FFFFFFF),
		}
		c := &Client{d2: d2}

		_, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, renewed))
		if err == nil || !strings.Contains(err.Error(), "CA reported 2147483647 signing certificates") {
			t.Fatalf("err = %v, want count error", err)
		}
		if len(d2.calls) != 1 {
			t.Fatalf("GetCAProperty indexes = %v, want only [%d]", d2.calls, propIndexCurrent)
		}
	})

	t.Run("rejects a truncated signing certificate count", func(t *testing.T) {
		d2 := &fakeD2{
			chains:   map[int32][]byte{0: degeneratePKCS7(t, original.cert, root.cert)},
			countBuf: []byte{1, 0},
		}
		c := &Client{d2: d2}

		_, err := c.getChainPem(context.Background(), "CA", issueLeaf(t, renewed))
		if err == nil || !strings.Contains(err.Error(), "signing certificate count") {
			t.Fatalf("err = %v, want count error", err)
		}
	})
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sub"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseIssuedCert(t *testing.T) {
	root := newTestCA(t, "root", nil)
	issuing := newTestCA(t, "issuing", root)
	sub := newTestCA(t, "sub", issuing)
	csr := csrFor(t, sub.key)

	t.Run("accepts a bare DER certificate", func(t *testing.T) {
		got, err := parseIssuedCert(sub.cert.Raw, csr)
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject.CommonName != "sub" {
			t.Fatalf("subject = %q, want sub", got.Subject.CommonName)
		}
	})

	t.Run("picks the CA certificate matching the CSR key out of a PKCS#7 bundle", func(t *testing.T) {
		bundle := degeneratePKCS7(t, root.cert, issuing.cert, sub.cert)
		got, err := parseIssuedCert(bundle, csr)
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject.CommonName != "sub" {
			t.Fatalf("subject = %q, want sub", got.Subject.CommonName)
		}
	})

	t.Run("rejects a PKCS#7 bundle that holds no certificate for the CSR key", func(t *testing.T) {
		leaf := issueLeaf(t, issuing)
		bundle := degeneratePKCS7(t, root.cert, issuing.cert, leaf)
		_, err := parseIssuedCert(bundle, csr)
		if err == nil || !strings.Contains(err.Error(), "none for the CSR's public key") {
			t.Fatalf("err = %v, want a no-matching-key error", err)
		}
	})

	t.Run("falls back to the first non-CA certificate when the CSR is unusable", func(t *testing.T) {
		leaf := issueLeaf(t, issuing)
		bundle := degeneratePKCS7(t, root.cert, issuing.cert, leaf)
		got, err := parseIssuedCert(bundle, []byte("not a csr"))
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject.CommonName != "leaf" {
			t.Fatalf("subject = %q, want leaf", got.Subject.CommonName)
		}
	})

	t.Run("rejects a response that is neither a certificate nor PKCS#7", func(t *testing.T) {
		if _, err := parseIssuedCert([]byte("garbage"), csr); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestEnroll(t *testing.T) {
	root := newTestCA(t, "root", nil)
	original := newTestCA(t, "issuing-v0", root)
	renewed := newTestCA(t, "issuing-v1", root)
	sub := newTestCA(t, "sub", renewed)
	csr := csrFor(t, sub.key)

	t.Run("returns the issued intermediate with the chain that issued it", func(t *testing.T) {
		d2 := &fakeD2{
			issued: degeneratePKCS7(t, root.cert, sub.cert, renewed.cert),
			chains: map[int32][]byte{
				propIndexCurrent: degeneratePKCS7(t, renewed.cert, root.cert),
				0:                degeneratePKCS7(t, original.cert, root.cert),
				1:                degeneratePKCS7(t, renewed.cert, root.cert),
			},
		}
		c := &Client{d2: d2}

		res, err := c.Enroll(context.Background(), "CA", "SubCA", csr)
		if err != nil {
			t.Fatal(err)
		}
		if subjects := pemSubjects(t, res.CertificatePem); strings.Join(subjects, ",") != "sub" {
			t.Fatalf("certificate subjects = %v, want [sub]", subjects)
		}
		if subjects := pemSubjects(t, res.ChainPem); strings.Join(subjects, ",") != "issuing-v1,root" {
			t.Fatalf("chain subjects = %v, want [issuing-v1 root]", subjects)
		}
	})

	t.Run("keeps the issued certificate when no CA chain issued it", func(t *testing.T) {
		d2 := &fakeD2{
			issued: degeneratePKCS7(t, sub.cert),
			chains: map[int32][]byte{
				propIndexCurrent: degeneratePKCS7(t, original.cert, root.cert),
				0:                degeneratePKCS7(t, original.cert, root.cert),
			},
		}
		c := &Client{d2: d2}

		res, err := c.Enroll(context.Background(), "CA", "SubCA", csr)
		if err != nil {
			t.Fatal(err)
		}
		if res.RequestID != 42 || res.Disposition != dispositionIssued {
			t.Fatalf("result = %+v, want request 42 issued", res)
		}
		if subjects := pemSubjects(t, res.CertificatePem); strings.Join(subjects, ",") != "sub" {
			t.Fatalf("certificate subjects = %v, want [sub]", subjects)
		}
		if subjects := pemSubjects(t, res.ChainPem); strings.Join(subjects, ",") != "issuing-v0,root" {
			t.Fatalf("best-effort chain subjects = %v, want [issuing-v0 root]", subjects)
		}
	})
}
