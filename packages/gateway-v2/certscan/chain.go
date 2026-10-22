package certscan

import (
	"bytes"
	"crypto/x509"
)

const maxChainLength = 10

func isCACert(c *x509.Certificate) bool {
	if c.BasicConstraintsValid && !c.IsCA {
		return false
	}
	if len(c.DNSNames) > 0 || len(c.IPAddresses) > 0 {
		return false
	}
	if c.BasicConstraintsValid {
		return true
	}
	return isSelfIssued(c) && c.KeyUsage&x509.KeyUsageCertSign != 0
}

func isSelfIssued(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject)
}

func dedupeCertificates(certs []*x509.Certificate) []*x509.Certificate {
	seen := make(map[string]bool, len(certs))
	out := make([]*x509.Certificate, 0, len(certs))
	for _, c := range certs {
		key := string(c.Raw)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

func findIssuer(cert *x509.Certificate, pool []*x509.Certificate, visited map[int]bool) int {
	match := -1
	for i, candidate := range pool {
		if visited[i] || candidate == cert || !bytes.Equal(candidate.RawSubject, cert.RawIssuer) {
			continue
		}
		if len(cert.AuthorityKeyId) > 0 && len(candidate.SubjectKeyId) > 0 {
			if bytes.Equal(cert.AuthorityKeyId, candidate.SubjectKeyId) {
				return i
			}
			continue
		}
		if match == -1 {
			match = i
		}
	}
	return match
}

func buildChains(certs []*x509.Certificate) []Chain {
	pool := dedupeCertificates(certs)
	used := make(map[int]bool, len(pool))
	var chains []Chain

	for i, cert := range pool {
		if isCACert(cert) {
			continue
		}
		used[i] = true
		chain := Chain{Kind: ChainKindLeaf, Certificates: [][]byte{cert.Raw}}
		visited := map[int]bool{i: true}
		current := cert
		for !isSelfIssued(current) && len(chain.Certificates) < maxChainLength {
			next := findIssuer(current, pool, visited)
			if next == -1 {
				break
			}
			visited[next] = true
			used[next] = true
			chain.Certificates = append(chain.Certificates, pool[next].Raw)
			current = pool[next]
		}
		chains = append(chains, chain)
	}

	for i, cert := range pool {
		if used[i] {
			continue
		}
		chains = append(chains, Chain{Kind: ChainKindCA, Certificates: [][]byte{cert.Raw}})
	}
	return chains
}

func chainFromOrdered(certs []*x509.Certificate) []Chain {
	certs = dedupeCertificates(certs)
	if len(certs) == 0 {
		return nil
	}
	chain := Chain{Kind: ChainKindLeaf}
	for _, c := range certs {
		chain.Certificates = append(chain.Certificates, c.Raw)
	}
	return []Chain{chain}
}
