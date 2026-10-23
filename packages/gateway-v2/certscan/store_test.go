package certscan

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func chainDER(t *testing.T, resp StoreScanResponse, r StoreCertificateResult) [][]byte {
	t.Helper()
	if len(r.Chains) != 1 {
		t.Fatalf("expected one chain, got %d", len(r.Chains))
	}
	out := make([][]byte, 0, len(r.Chains[0].Indexes))
	for _, idx := range r.Chains[0].Indexes {
		out = append(out, resp.Pool[idx])
	}
	return out
}

func TestBuildStoreResultsCompletesChainFromIssuerStores(t *testing.T) {
	p := newTestPKI(t)
	resp := BuildStoreResults([]StoreCertificate{
		{Store: "CA", Thumbprint: "BB", DER: p.inter.Raw},
		{Store: "Root", Thumbprint: "CC", DER: p.root.Raw},
		{Store: "My", Thumbprint: "AA", HasPrivateKey: true, Requested: true, DER: p.leaf.Raw},
	})

	if len(resp.Certificates) != 1 {
		t.Fatalf("expected only the requested certificate, got %d results", len(resp.Certificates))
	}
	r := resp.Certificates[0]
	if r.Status != StatusOK || !r.HasPrivateKey || r.Store != "My" || r.Thumbprint != "AA" || r.Chains[0].Kind != ChainKindLeaf {
		t.Fatalf("unexpected result: %+v", r)
	}
	got := chainDER(t, resp, r)
	if len(got) != 3 || !bytes.Equal(got[0], p.leaf.Raw) || !bytes.Equal(got[1], p.inter.Raw) || !bytes.Equal(got[2], p.root.Raw) {
		t.Fatalf("expected leaf, intermediate, root; got %d certificates", len(got))
	}
}

func TestBuildStoreResultsSharesIssuersInThePool(t *testing.T) {
	p := newTestPKI(t)
	second := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "web.example.com"}, DNSNames: []string{"web.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true,
	}, p.inter, &p.leafKey.PublicKey, p.interKey)
	resp := BuildStoreResults([]StoreCertificate{
		{Store: "CA", Thumbprint: "BB", DER: p.inter.Raw},
		{Store: "Root", Thumbprint: "CC", DER: p.root.Raw},
		{Store: "My", Thumbprint: "AA", Requested: true, DER: p.leaf.Raw},
		{Store: "My", Thumbprint: "DD", Requested: true, DER: second.Raw},
	})
	if len(resp.Certificates) != 2 || len(resp.Pool) != 4 {
		t.Fatalf("expected 2 results over a pool of 4 unique certificates, got %d results and %d pooled", len(resp.Certificates), len(resp.Pool))
	}
}

func TestBuildStoreResultsPrefersValidSelfSignedRootOverExpiredCrossSign(t *testing.T) {
	p := newTestPKI(t)
	oldRootKey := mustKey(t)
	oldRootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "Old Root"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{9},
	}
	oldRoot := mustCert(t, oldRootTmpl, oldRootTmpl, &oldRootKey.PublicKey, oldRootKey)
	crossSigned := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(21), Subject: p.root.Subject,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{1},
	}, oldRoot, &p.rootKey.PublicKey, oldRootKey)

	resp := BuildStoreResults([]StoreCertificate{
		{Store: "CA", Thumbprint: "XS", DER: crossSigned.Raw},
		{Store: "CA", Thumbprint: "BB", DER: p.inter.Raw},
		{Store: "Root", Thumbprint: "OR", DER: oldRoot.Raw},
		{Store: "Root", Thumbprint: "CC", DER: p.root.Raw},
		{Store: "My", Thumbprint: "AA", Requested: true, DER: p.leaf.Raw},
	})
	got := chainDER(t, resp, resp.Certificates[0])
	if len(got) != 3 || !bytes.Equal(got[2], p.root.Raw) {
		t.Fatalf("expected the chain to end at the valid self-signed root, got %d certificates", len(got))
	}
}

func TestBuildStoreResultsStopsAtTheResponseBudget(t *testing.T) {
	p := newTestPKI(t)
	certs := []StoreCertificate{{Store: "Root", Thumbprint: "CC", DER: p.root.Raw}, {Store: "CA", Thumbprint: "BB", DER: p.inter.Raw}}
	for i := 0; i < 5; i++ {
		leaf := mustCert(t, &x509.Certificate{
			SerialNumber: big.NewInt(int64(100 + i)), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: []string{"leaf.example.com"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true,
		}, p.inter, &p.leafKey.PublicKey, p.interKey)
		certs = append(certs, StoreCertificate{Store: "My", Thumbprint: string(rune('A' + i)), Requested: true, DER: leaf.Raw})
	}
	budget := len(p.root.Raw) + len(p.inter.Raw) + 2*len(certs[2].DER) + 10
	resp := buildStoreResults(certs, budget, time.Now())
	if resp.TruncatedReason != TruncatedResponseSize || len(resp.Certificates) != 2 {
		t.Fatalf("expected 2 results and a responseSize cut, got %d results and %q", len(resp.Certificates), resp.TruncatedReason)
	}
}

func TestBuildStoreResultsReportsRequestedCAAsCAChain(t *testing.T) {
	p := newTestPKI(t)
	resp := BuildStoreResults([]StoreCertificate{
		{Store: "Root", Thumbprint: "CC", Requested: true, DER: p.root.Raw},
	})
	if len(resp.Certificates) != 1 || resp.Certificates[0].Chains[0].Kind != ChainKindCA || len(resp.Certificates[0].Chains[0].Indexes) != 1 {
		t.Fatalf("expected a single CA chain, got %+v", resp.Certificates)
	}
}

func TestBuildStoreResultsMarksUnparseableCertificates(t *testing.T) {
	resp := BuildStoreResults([]StoreCertificate{
		{Store: "My", Thumbprint: "DD", Requested: true, DER: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
	})
	if len(resp.Certificates) != 1 || resp.Certificates[0].Status != StatusParseError || len(resp.Certificates[0].Chains) != 0 {
		t.Fatalf("expected a parse error, got %+v", resp.Certificates)
	}
}

func TestBuildStoreResultsDedupesByStoreAndThumbprint(t *testing.T) {
	p := newTestPKI(t)
	resp := BuildStoreResults([]StoreCertificate{
		{Store: "My", Thumbprint: "AA", Requested: true, DER: p.leaf.Raw},
		{Store: "My", Thumbprint: "AA", Requested: true, DER: p.leaf.Raw},
		{Store: "WebHosting", Thumbprint: "AA", Requested: true, DER: p.leaf.Raw},
	})
	if len(resp.Certificates) != 2 {
		t.Fatalf("expected one result per store, got %d", len(resp.Certificates))
	}
}
