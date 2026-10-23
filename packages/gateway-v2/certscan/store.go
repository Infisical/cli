package certscan

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

// Chains index into the shared Pool, so the budget counts each certificate once.
const maxStoreResponseBytes = 12 * 1024 * 1024

// Requested is false for certificates read only to build chains.
type StoreCertificate struct {
	Store         string
	Thumbprint    string
	HasPrivateKey bool
	Requested     bool
	DER           []byte
}

type StoreChain struct {
	Kind    ChainKind `json:"kind"`
	Indexes []int     `json:"indexes"`
}

type StoreCertificateResult struct {
	Store         string       `json:"store"`
	Thumbprint    string       `json:"thumbprint"`
	HasPrivateKey bool         `json:"hasPrivateKey"`
	Status        FileStatus   `json:"status"`
	Chains        []StoreChain `json:"chains"`
}

type StoreScanResponse struct {
	Host         HostInfo                 `json:"host"`
	Pool         [][]byte                 `json:"pool"`
	Certificates []StoreCertificateResult `json:"certificates"`
	DeniedStores []string                 `json:"deniedStores"`
	// Issuer stores the scan reads for chains but couldn't open, so chains may stop early.
	UnreadableIssuerStores []string `json:"unreadableIssuerStores"`
	// Issuer stores with more certificates than the scan reads for chains.
	TruncatedIssuerStores []string        `json:"truncatedIssuerStores"`
	TruncatedReason       TruncatedReason `json:"truncatedReason,omitempty"`
}

type storeResultBuilder struct {
	pool    [][]byte
	indexOf map[string]int
	size    int
	budget  int
}

func (b *storeResultBuilder) add(certs []*x509.Certificate) ([]int, bool) {
	extra := 0
	for _, c := range certs {
		if _, ok := b.indexOf[string(c.Raw)]; !ok {
			extra += len(c.Raw)
		}
	}
	if b.size+extra > b.budget {
		return nil, false
	}
	indexes := make([]int, 0, len(certs))
	for _, c := range certs {
		key := string(c.Raw)
		idx, ok := b.indexOf[key]
		if !ok {
			idx = len(b.pool)
			b.indexOf[key] = idx
			b.pool = append(b.pool, c.Raw)
			b.size += len(c.Raw)
		}
		indexes = append(indexes, idx)
	}
	return indexes, true
}

func BuildStoreResults(certs []StoreCertificate) StoreScanResponse {
	return buildStoreResults(certs, maxStoreResponseBytes, time.Now())
}

func buildStoreResults(certs []StoreCertificate, budget int, now time.Time) StoreScanResponse {
	parsed := make([]*x509.Certificate, len(certs))
	var all []*x509.Certificate
	for i, c := range certs {
		cert, err := x509.ParseCertificate(c.DER)
		if err != nil {
			continue
		}
		parsed[i] = cert
		all = append(all, cert)
	}
	issuers := newIssuerIndex(dedupeCertificates(all))

	builder := &storeResultBuilder{indexOf: map[string]int{}, budget: budget}
	response := StoreScanResponse{Pool: [][]byte{}, Certificates: []StoreCertificateResult{}}
	seen := make(map[string]bool, len(certs))
	for i, c := range certs {
		if !c.Requested {
			continue
		}
		key := c.Store + "\x00" + c.Thumbprint
		if seen[key] {
			continue
		}
		seen[key] = true

		result := StoreCertificateResult{Store: c.Store, Thumbprint: c.Thumbprint, HasPrivateKey: c.HasPrivateKey}
		cert := parsed[i]
		if cert == nil {
			result.Status = StatusParseError
			response.Certificates = append(response.Certificates, result)
			continue
		}
		kind, chain := chainForStoreCertificate(cert, issuers, now)
		indexes, ok := builder.add(chain)
		if !ok {
			response.TruncatedReason = TruncatedResponseSize
			continue
		}
		result.Status = StatusOK
		result.Chains = []StoreChain{{Kind: kind, Indexes: indexes}}
		response.Certificates = append(response.Certificates, result)
	}
	response.Pool = builder.pool
	if response.Pool == nil {
		response.Pool = [][]byte{}
	}
	return response
}

type issuerIndex struct {
	bySubject map[string][]*x509.Certificate
}

func newIssuerIndex(certs []*x509.Certificate) issuerIndex {
	idx := issuerIndex{bySubject: map[string][]*x509.Certificate{}}
	for _, c := range certs {
		idx.bySubject[string(c.RawSubject)] = append(idx.bySubject[string(c.RawSubject)], c)
	}
	return idx
}

func chainForStoreCertificate(cert *x509.Certificate, issuers issuerIndex, now time.Time) (ChainKind, []*x509.Certificate) {
	if isCACert(cert) {
		return ChainKindCA, []*x509.Certificate{cert}
	}
	chain := []*x509.Certificate{cert}
	visited := map[string]bool{string(cert.Raw): true}
	current := cert
	for !isSelfSigned(current) && len(chain) < maxChainLength {
		next := findStoreIssuer(current, issuers.bySubject[string(current.RawIssuer)], visited, now)
		if next == nil {
			break
		}
		visited[string(next.Raw)] = true
		chain = append(chain, next)
		current = next
	}
	return ChainKindLeaf, chain
}

// signedBy reports whether parent's key signed child; checked is false when Go refuses the algorithm (MD5, SHA-1).
func signedBy(child, parent *x509.Certificate) (ok, checked bool) {
	err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	if err == nil {
		return true, true
	}
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		return true, false
	}
	return false, false
}

// A self-issued certificate can be signed by a previous CA key during a rollover, so names alone don't end a chain.
func isSelfSigned(c *x509.Certificate) bool {
	if !isSelfIssued(c) {
		return false
	}
	ok, _ := signedBy(c, c)
	return ok
}

// Prefers a valid, self-signed issuer: Windows CA stores keep expired cross-signed copies of roots.
func findStoreIssuer(cert *x509.Certificate, candidates []*x509.Certificate, visited map[string]bool, now time.Time) *x509.Certificate {
	var best *x509.Certificate
	bestScore := -1
	for _, candidate := range candidates {
		if visited[string(candidate.Raw)] {
			continue
		}
		if len(cert.AuthorityKeyId) > 0 && len(candidate.SubjectKeyId) > 0 &&
			!bytes.Equal(cert.AuthorityKeyId, candidate.SubjectKeyId) {
			continue
		}
		ok, checked := signedBy(cert, candidate)
		if !ok {
			continue
		}
		score := 0
		if checked {
			score += 8
		}
		if !now.Before(candidate.NotBefore) && !now.After(candidate.NotAfter) {
			score += 4
		}
		if isSelfSigned(candidate) {
			score++
		}
		if score > bestScore {
			best, bestScore = candidate, score
		}
	}
	return best
}
